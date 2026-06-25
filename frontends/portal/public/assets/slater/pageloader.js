// pageloader.js - local copy (patched for CSS translate handling)

var pageLoadTimeline;

function startPageLoad() {
  // Reset CSS translate immediately — GSAP's y/transform won't override it
  document.querySelectorAll('header, section').forEach(function(el) {
    el.style.translate  = '0rem 0rem';
    el.style.willChange = 'inherit';
  });
  document.querySelectorAll('nav').forEach(function(el) {
    el.style.translate = '0rem 0rem';
  });

  pageLoadTimeline = gsap.timeline();

  pageLoadTimeline
    // Darken columns
    .to('.page_loader_column', {
      backgroundColor: 'rgba(50,50,50,0.35)',
      ease: 'power2.out', duration: 1,
      stagger: { amount: 0.25, from: 'center' }
    })
    // Collapse columns
    .to('.page_loader_column', {
      scaleY: 0, duration: 0.875, ease: 'power2.out',
      stagger: { amount: 0.1, from: 'random' }
    }, '-=0.5')
    // Fade out loader content
    .to('.page_loader_content', { opacity: 0, duration: 0.5 }, '<')
    .to('.page_loader_wrap .noise_overlay', { opacity: 0, duration: 0.5 }, '<')
    // Fade in sections
    .fromTo('header, section',
      { opacity: 0, y: '-1.5rem' },
      { opacity: 1, y: 0, duration: 0.9, ease: 'power2.out', stagger: 0.06,
        onComplete: function() {
          document.querySelectorAll('header, section').forEach(function(el) {
            el.style.transform  = 'none';
            el.style.opacity    = '';
          });
          if (window.ScrollTrigger) ScrollTrigger.refresh();
        }
      }, '<')
    // Hide loader wrap entirely when done
    .call(function() {
      var l = document.querySelector('.page_loader_wrap');
      if (l) { l.style.display = 'none'; }
    });
}

var hasAnimatedOnLoad = false;
if (window.isInitialized && !hasAnimatedOnLoad) { startPageLoad(); hasAnimatedOnLoad = true; }
$(document).on('cm:init', function() {
  if (!hasAnimatedOnLoad) { startPageLoad(); hasAnimatedOnLoad = true; }
});

// Page-out animation (link clicks)
function startPageOut(url) {
  var tl = gsap.timeline({ onComplete: function() { window.location.href = url; } });
  tl.to('header, section, footer, .cases_bg', { y: '4rem', duration: 0.75, ease: 'power2.out' })
    .to('.page_loader_wrap .noise_overlay', { opacity: 0.05, duration: 0.5 }, '<')
    .to('.page_loader_content', { opacity: 1, duration: 0.5 }, '<')
    .to('.page_loader_column', { scaleY: 1, duration: 0.75, ease: 'power2.out', stagger: { amount: 0.1, from: 'random' }, transformOrigin: 'top' }, '<')
    .to('.page_loader_column', { backgroundColor: 'rgba(0,0,0,1)', ease: 'power2.out', duration: 0.75 }, '<');
}

$(document).on('click', 'a', function(e) {
  var ch = window.location.hostname, th = e.currentTarget.hostname;
  var tp = e.currentTarget.pathname, cp = window.location.pathname;
  if (th && th !== ch) { e.preventDefault(); window.open(e.currentTarget.href, '_blank'); return; }
  if (th === ch && tp !== cp) { e.preventDefault(); startPageOut(e.currentTarget.href); }
});
