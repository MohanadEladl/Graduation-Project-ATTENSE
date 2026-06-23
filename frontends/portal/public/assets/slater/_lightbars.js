// _lightbars.js - local copy
let currentMainColor = typeof globalColorMain != "undefined" ? globalColorMain : "#FF819F";
let currentAltColor  = typeof globalColorAlt  != "undefined" ? globalColorAlt  : "#09326a";
$('.lightbar_row').each(function () {
  const bars = $(this).find('.lightbar_bar');
  bars.each(function (i) {
    const p = i / Math.max(bars.length - 1, 1);
    $(this).css('background-color', gsap.utils.interpolate(currentMainColor, currentAltColor, p));
  });
  gsap.fromTo(bars, { opacity: 0.2 }, { opacity: 1, duration: 0.75, stagger: { each: 0.075, amount: Math.random()*2+1, from:"random" }, repeat:-1, yoyo:true, ease:"power1.inOut" });
});
$(document).on("cm:new_case", function () {
  setTimeout(function () {
    $('.lightbar_row').each(function () {
      const bars = $(this).find('.lightbar_bar');
      bars.each(function (i) {
        const p = i / Math.max(bars.length - 1, 1);
        gsap.to(this, { backgroundColor: gsap.utils.interpolate(globalColorMain, globalColorAlt, p), duration:2, ease:"power2.inOut" });
      });
    });
    currentMainColor = globalColorMain; currentAltColor = globalColorAlt;
  }, 10);
});
(function(){
  const $ctaTeam = $('#cta-team'); if($ctaTeam.length===0) return;
  function isIntersecting(r1,r2){return !(r1.right<r2.left||r1.left>r2.right||r1.bottom<r2.top||r1.top>r2.bottom);}
  function placeMembers(){
    const $members=$('#cta-team .member'); const $blocks=$('.community_cta-component .lightbar_row .lightbar_block');
    if(!$members.length||!$blocks.length) return;
    const obstacles=[];$('.col').each(function(){obstacles.push(this.getBoundingClientRect());});
    const $avail=$blocks.filter(function(){const r=this.getBoundingClientRect();return !obstacles.some(o=>isIntersecting(r,o));});
    if(!$avail.length) return;
    const idx=Array.from({length:$avail.length},(_,i)=>i);
    for(let i=idx.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[idx[i],idx[j]]=[idx[j],idx[i]];}
    const minD=Math.max(2,Math.floor($avail.length/($members.length*1.5)));
    const sel=[];
    for(let i=0;i<idx.length&&sel.length<$members.length;i++){if(!sel.some(s=>Math.abs(s-idx[i])<minD))sel.push(idx[i]);}
    while(sel.length<$members.length){const rem=idx.filter(i=>!sel.includes(i));if(!rem.length)break;sel.push(rem[Math.floor(Math.random()*rem.length)]);}
    $members.each(function(i){if(i<sel.length)$(this).css('position','absolute').appendTo($avail.eq(sel[i]));});
  }
  placeMembers();
})();