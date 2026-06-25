// home_components.js - local copy
(()=>{
  const $skills=$(".skills_item"),$list=$(".skills_list");
  let activeId=null,mode=null,isMouseOverList=false,resizeTimer=null,desktopScrollHandler=null;
  const timelines=new Map();
  const getId=$el=>$el.attr("data-skill-id")||String($el.index());
  const qsa=(sel,root=document)=>Array.from(root.querySelectorAll(sel));
  const killAll=()=>{gsap.killTweensOf(".skills_item-list > *");gsap.killTweensOf(".skills_item");timelines.forEach(tl=>tl.kill());timelines.clear();};
  const hardReset=()=>{killAll();gsap.set($(".skills_item-list > *"),{opacity:0,x:"-0.5rem"});$skills.removeClass("active");};
  const getOrCreate=$item=>{const id=getId($item);if(timelines.has(id))return timelines.get(id);const $tags=$item.find(".skills_item-list > *");const tl=gsap.timeline({paused:true});tl.set($tags,{opacity:0,x:"-0.5rem"});tl.to($tags,{opacity:1,x:"0rem",duration:0.5,ease:"power4.out",stagger:0.05});timelines.set(id,tl);return tl;};
  const activate=$item=>{if(!$item||!$item.length)return;const id=getId($item);if(activeId===id&&$item.hasClass("active"))return;$skills.each((_,el)=>{const $el=$(el);const oid=getId($el);if(oid!==id){$el.removeClass("active");const tl=timelines.get(oid);if(tl)tl.kill();timelines.delete(oid);gsap.set($el.find(".skills_item-list > *"),{opacity:0,x:"-0.5rem"});}});$item.addClass("active");activeId=id;timelines.set(id,getOrCreate($item));timelines.get(id).play(0);};
  const deactivateAll=()=>{activeId=null;hardReset();};
  const debounce=(fn,wait)=>{let t;return(...args)=>{clearTimeout(t);t=setTimeout(()=>fn(...args),wait);};};
  const rafThrottle=fn=>{let ticking=false;return(...args)=>{if(ticking)return;ticking=true;requestAnimationFrame(()=>{fn(...args);ticking=false;});};};
  const wireMobile=()=>{mode="mobile";deactivateAll();const onScrollCore=()=>{const vh=window.innerHeight,center=vh/2;let best=null,bestD=Infinity;qsa(".skills_item").forEach(el=>{const r=el.getBoundingClientRect();if(!(r.bottom>0&&r.top<vh))return;const ic=r.top+r.height/2,d=Math.abs(ic-center);const inZone=ic>vh*0.42&&ic<vh*0.58;if(inZone&&d<bestD){best=el;bestD=d;}});if(best)activate($(best));};const onScroll=rafThrottle(onScrollCore);if(window.lenis)window.lenis.on("scroll",onScroll);else ScrollTrigger.create({trigger:document.body,start:"top top",end:"bottom bottom",onUpdate:onScroll,refreshPriority:-1});setTimeout(onScrollCore,50);};
  const wireDesktop=()=>{mode="desktop";deactivateAll();isMouseOverList=false;const hoverIntent=debounce(($el)=>{if(isMouseOverList)activate($el);},10);$list.on("mouseenter",()=>{isMouseOverList=true;});$list.on("mouseleave",()=>{isMouseOverList=false;deactivateAll();});$skills.on("mouseenter",function(){if(!isMouseOverList)return;hoverIntent($(this));});$skills.on("mouseleave",function(){const $t=$(this);const id=getId($t);const tl=timelines.get(id);if(tl)tl.pause(0);gsap.set($t.find(".skills_item-list > *"),{opacity:$t.hasClass("active")?1:0,x:$t.hasClass("active")?"0rem":"-0.5rem"});});desktopScrollHandler=debounce(()=>{const r=$list[0]?.getBoundingClientRect();if(!r)return;if(!(r.bottom>0&&r.top<window.innerHeight))deactivateAll();},120);if(window.lenis)window.lenis.on("scroll",desktopScrollHandler);else window.addEventListener("scroll",desktopScrollHandler,{passive:true});};
  const setup=()=>{if(window.innerWidth<992)wireMobile();else wireDesktop();if(!window.lenis&&window.ScrollTrigger)ScrollTrigger.refresh();};
  setup();window.addEventListener("resize",()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(setup,200);});
})();