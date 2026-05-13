(function ($) {
    "use strict";

    // Spinner
    var spinner = function () {
        setTimeout(function () {
            if ($('#spinner').length > 0) {
                $('#spinner').removeClass('show');
            }
        }, 1);
    };
    spinner();
    
    
    // Initiate the wowjs
    new WOW().init();


    // Sticky Navbar
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.sticky-top').addClass('shadow-sm').css('top', '0px');
        } else {
            $('.sticky-top').removeClass('shadow-sm').css('top', '-100px');
        }
    });
    
    
    // Back to top button
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.back-to-top').fadeIn('slow');
        } else {
            $('.back-to-top').fadeOut('slow');
        }
    });
    $('.back-to-top').click(function () {
        $('html, body').animate({scrollTop: 0}, 1500, 'easeInOutExpo');
        return false;
    });


    // Testimonials carousel
    $(".testimonial-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1000,
        items: 1,
        dots: true,
        loop: true,
    });

    
})(jQuery);

(function () {
    if (window.__amtelAnalyticsInstalled) {
        return;
    }
    window.__amtelAnalyticsInstalled = true;

    var activeSeconds = 0;
    var maxScrollPercent = 0;
    var lastTick = Date.now();

    function postAnalytics(url, payload) {
        var body = JSON.stringify(payload);
        if (navigator.sendBeacon) {
            navigator.sendBeacon(url, new Blob([body], { type: 'application/json' }));
            return;
        }
        fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body,
            keepalive: true
        }).catch(function () {});
    }

    function basePayload() {
        return {
            path: window.location.pathname,
            page_title: document.title
        };
    }

    function describeClickable(element) {
        var target = element.closest('button, a, input[type="button"], input[type="submit"], .btn');
        if (!target || target.closest('[data-analytics-ignore="true"]')) {
            return null;
        }
        var text = (target.innerText || target.value || target.getAttribute('aria-label') || target.title || '').trim();
        return {
            path: basePayload().path,
            page_title: basePayload().page_title,
            element_text: text.substring(0, 255),
            element_type: target.tagName.toLowerCase(),
            element_id: target.id || '',
            element_classes: target.className ? String(target.className).substring(0, 255) : '',
            target_url: target.href || target.formAction || ''
        };
    }

    document.addEventListener('click', function (event) {
        var payload = describeClickable(event.target);
        if (!payload) {
            return;
        }
        postAnalytics('/analytics/click', payload);
        if (/^mailto:/i.test(payload.target_url || '') && /apply/i.test(payload.element_text || payload.target_url || '')) {
            postAnalytics('/analytics/conversion', {
                path: payload.path,
                page_title: payload.page_title,
                conversion_type: 'job_apply_click',
                target: payload.target_url,
                value_label: payload.element_text || 'Apply'
            });
        }
    }, true);

    window.addEventListener('scroll', function () {
        var scrollable = document.documentElement.scrollHeight - window.innerHeight;
        if (scrollable <= 0) {
            maxScrollPercent = 100;
            return;
        }
        maxScrollPercent = Math.max(maxScrollPercent, Math.min(100, Math.round((window.scrollY / scrollable) * 100)));
    }, { passive: true });

    setInterval(function () {
        var now = Date.now();
        if (!document.hidden) {
            activeSeconds += Math.min(10, Math.round((now - lastTick) / 1000));
        }
        lastTick = now;
    }, 1000);

    function sendEngagement() {
        if (activeSeconds <= 0 && maxScrollPercent <= 0) {
            return;
        }
        postAnalytics('/analytics/engagement', Object.assign(basePayload(), {
            active_seconds: activeSeconds,
            max_scroll_percent: maxScrollPercent
        }));
    }

    document.addEventListener('visibilitychange', function () {
        if (document.hidden) {
            sendEngagement();
        }
    });
    window.addEventListener('pagehide', sendEngagement);
}());

