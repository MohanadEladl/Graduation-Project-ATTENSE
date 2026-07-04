// __main_new.js - local copy
gsap.registerPlugin(ScrollTrigger);
gsap.registerPlugin(CustomEase);
CustomEase.create("main","M0,0 C0.131,0 0.254,0.194 0.3,0.4 0.428,0.977 0.677,0.997 1,1 ");

// Marquee
$(".logo_carousel_content").after($(".logo_carousel_content").clone());
let marqueeExists=$(".logo_carousel_wrap").length>0;
let lastScroll=0,lastDirection='down',targetTimeScale=1,currentTimeScale=1;
let tlDuration=$(".logo_carousel_content").outerWidth()/50;
const marqueeTl=gsap.timeline({repeat:-1});
if(marqueeExists){
  marqueeTl.to(".logo_carousel_content",{duration:tlDuration,xPercent:-100,ease:'none'});
  setInterval(function(){if(marqueeTl.progress()===0&&lastDirection==='up')marqueeTl.seek(tlDuration);},50);
  gsap.to(".logo_carousel_wrap",{scrollTrigger:{trigger:".logo_carousel_wrap",start:"top bottom",end:"bottom top",scrub:1.5},xPercent:-10});
}
$(window).on('scroll',function(){
  let cs=$(this).scrollTop();
  if(cs>lastScroll){targetTimeScale=1;lastDirection='down';}else{targetTimeScale=-1;lastDirection='up';}
  if(targetTimeScale!=currentTimeScale&&marqueeExists){marqueeTl.timeScale(targetTimeScale);currentTimeScale=targetTimeScale;}
  lastScroll=cs;
});
lastScroll=$(window).scrollTop();

// Custom cursor
function initCustomCursor(){
  if(window.matchMedia("(pointer:fine)").matches){
    const $cursor=$("#cursor"),$circle=$("#cursor-follow"),$label=$("#cursor-label");
    $cursor.hide();
    gsap.set($label,{width:0,scale:0,opacity:0});
    gsap.set($circle,{scale:0});
    function showLabel(text){$label.text(text);gsap.to($label,{width:"auto",duration:0.5,ease:"main"});gsap.to($label,{scale:1,duration:0.3,ease:"main"});gsap.to($label,{opacity:1,duration:0.15,ease:"none"});gsap.to($cursor,{scale:0.5,duration:0.3,ease:"main"});}
    function hideLabel(){gsap.to($label,{width:0,duration:0.15,ease:"main"});gsap.to($label,{scale:0,duration:0.25,ease:"main"});gsap.to($label,{opacity:0,duration:0.15,ease:"none"});gsap.to($cursor,{scale:1,duration:0.3,ease:"main"});}
    if($cursor.length){
      var $fixed=$("#cursor").parent();
      gsap.set($cursor,{opacity:1});
      $(document).on("pointermove",function(e){
        $cursor.show();
        let cw=$cursor.width(),ch=$cursor.height(),fo=$fixed.offset();
        gsap.set($cursor,{top:e.pageY-fo.top-ch/2+8,left:e.pageX-fo.left-cw/2+8});
        gsap.to($label,{duration:1,delay:0.05,ease:"power4.out",top:e.pageY-fo.top-ch/2+16,left:e.pageX-fo.left-cw/2+16});
        gsap.to($circle,{duration:1,delay:0.02,ease:"power4.out",top:e.pageY-fo.top-ch/2-$circle.width()*0.25-4,left:e.pageX-fo.left-cw/2-$circle.width()*0.25-4});
      });
      $("[data-label]").on("mouseenter",function(e){showLabel($(this).attr("data-label"));gsap.set($circle,{opacity:0,overwrite:true});});
      $("[data-label]").on("mouseleave",function(){hideLabel();gsap.set($circle,{opacity:1,delay:0.3});});
      $("a, [data-clickable]").on("mouseenter",function(){gsap.to($cursor,{rotate:22.5,scale:0.75,duration:0.2,ease:"main"});gsap.to($circle,{scale:1,duration:0.2,ease:"main"});});
      $("a, [data-clickable]").on("mouseleave",function(){gsap.to($cursor,{rotate:0,scale:1,duration:0.2,ease:"main"});gsap.to($circle,{scale:0,duration:0.2,ease:"main"});});
    }
    $("body").addClass("custom-cursor-active");
  } else {
    $(".custom-cursor").hide();
  }
}
initCustomCursor();
// Signal init complete
window.isInitialized = true;
$(document).trigger("cm:init");