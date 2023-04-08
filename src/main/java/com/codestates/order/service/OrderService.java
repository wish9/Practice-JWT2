package com.codestates.order.service;

import com.codestates.auth.CustomAuthorityUtils;
import com.codestates.auth.MemberDetailsService;
import com.codestates.coffee.service.CoffeeService;
import com.codestates.exception.BusinessLogicException;
import com.codestates.exception.ExceptionCode;
import com.codestates.helper.StampCalculator;
import com.codestates.member.entity.Member;
import com.codestates.member.service.MemberService;
import com.codestates.order.entity.Order;
import com.codestates.order.repository.OrderRepository;
import com.codestates.stamp.Stamp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Optional;

@Slf4j
@Transactional
@Service
public class OrderService {
    private final MemberService memberService;
    private final MemberDetailsService memberDetailsService;
    private final OrderRepository orderRepository;
    private final CoffeeService coffeeService;
    private final CustomAuthorityUtils authorityUtils;


    public OrderService(MemberService memberService,
                        MemberDetailsService memberDetailsService, OrderRepository orderRepository,
                        CoffeeService coffeeService, CustomAuthorityUtils authorityUtils) {
        this.memberService = memberService;
        this.memberDetailsService = memberDetailsService;
        this.orderRepository = orderRepository;
        this.coffeeService = coffeeService;
        this.authorityUtils = authorityUtils;
    }

    public Order createOrder(Order order) {
        verifyOrder(order);
        Order savedOrder = saveOrder(order);
        updateStamp(savedOrder);

        return savedOrder;
    }

    //    @PreAuthorize("authentication.name == @orderRepository.findById(#order.orderId).member.username or hasRole('ADMIN')") // 이렇게 하면 예외처리 힘듬
    @PreAuthorize("@orderService.isOrderOwnerOrAdmin(#order.orderId, authentication.name)")
    public Order updateOrder(Order order) {
        Order findOrder = findVerifiedOrder(order.getOrderId());

        Optional.ofNullable(order.getOrderStatus())
                .ifPresent(orderStatus -> findOrder.setOrderStatus(orderStatus));
        return orderRepository.save(findOrder);
    }

    @PreAuthorize("@orderService.isOrderOwnerOrAdmin(#orderId, authentication.name)") // 사용자가 해당 주문의 주인인지 or 관리자인지 확인
    public Order findOrder(long orderId) {
        return findVerifiedOrder(orderId);
    }

    public Page<Order> findOrders(int page, int size) {
        return orderRepository.findAll(PageRequest.of(page, size,
                Sort.by("orderId").descending()));
    }

    //    @PreAuthorize("authentication.name == @orderRepository.findById(#orderId).member.username or hasRole('ROLE_ADMIN')") // 이렇게 하면 예외처리 힘듬
    @PreAuthorize("@orderService.isOrderOwnerOrAdmin(#orderId, authentication.name)")
    public void cancelOrder(long orderId) {
        Order findOrder = findVerifiedOrder(orderId);
        int step = findOrder.getOrderStatus().getStepNumber();

        // OrderStatus의 step이 2 이상일 경우(ORDER_CONFIRM)에는 주문 취소가 되지 않도록한다.
        if (step >= 2) {
            throw new BusinessLogicException(ExceptionCode.CANNOT_CHANGE_ORDER);
        }
        findOrder.setOrderStatus(Order.OrderStatus.ORDER_CANCEL);
        orderRepository.save(findOrder);
    }

    private Order findVerifiedOrder(long orderId) {
        Optional<Order> optionalOrder = orderRepository.findById(orderId);
        Order findOrder =
                optionalOrder.orElseThrow(() ->
                        new BusinessLogicException(ExceptionCode.ORDER_NOT_FOUND));
        return findOrder;
    }

    private void verifyOrder(Order order) {
        // 회원이 존재하는지 확인
        memberService.findVerifiedMember(order.getMember().getMemberId());

        // 커피가 존재하는지 확인
        order.getOrderCoffees().stream()
                .forEach(orderCoffee -> coffeeService.
                        findVerifiedCoffee(orderCoffee.getCoffee().getCoffeeId()));
    }

    private void updateStamp(Order order) {
        Member member = memberService.findMember(order.getMember().getMemberId());
        int earnedStampCount = StampCalculator.calculateEarnedStampCount(order);

        Stamp stamp = member.getStamp();
        stamp.setStampCount(
                StampCalculator.calculateStampCount(stamp.getStampCount(),
                        earnedStampCount));
        member.setStamp(stamp);

        memberService.updateMember(member);
    }

    private int calculateStampCount(Order order) {
        return order.getOrderCoffees().stream()
                .map(orderCoffee -> orderCoffee.getQuantity())
                .mapToInt(quantity -> quantity)
                .sum();
    }

    private Order saveOrder(Order order) {
        return orderRepository.save(order);
    }

    public boolean isOrderOwnerOrAdmin(long orderId, String username) { // 주문주인 or 관리자인지 확인
        try {
            Optional<Order> optionalOrder = orderRepository.findById(orderId);
            if (optionalOrder.isPresent()) {
                Order order = optionalOrder.get();
                if (order.getMember() != null) {
                    UserDetails userDetails = memberDetailsService.loadUserByUsername(username);
                    Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

                    boolean isAdmin = authorities.stream()
                            .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));

                    return order.getMember().getName().equals(username) || isAdmin;
                } else { // 주문한 사용자가 아닐 때
                    log.error("본인 주문에만 접근 가능합니다.", orderId);
                }
            } else { // 주문이 없을 때 처리
                log.error("존재하지 않는 주문입니다.", orderId);
            }
        } catch (Exception e) { // 데이터베이스 연결 문제 등의 예외 처리
            log.error("주문 ID: {} 조회 중 오류가 발생했습니다. 오류: {}", orderId, e.getMessage());
        }
        return false;
    }
}
