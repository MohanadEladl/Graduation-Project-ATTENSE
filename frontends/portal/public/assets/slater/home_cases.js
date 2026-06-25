// home_cases.js - local copy
let activeItem=null;
const setupScrollTriggers=()=>{
  ScrollTrigger.getAll().forEach(t=>t.kill());
  if(activeItem){$(activeItem.item).removeClass("no-blur");activeItem=null;}
  if(window.innerWidth<992){
    gsap.utils.toArray(".home_case-item").forEach(item=>{
      ScrollTrigger.create({trigger:item,start:"top 67%",end:"bottom 33%",onUpdate:(self)=>{
        if(self.isActive){
          const r=item.getBoundingClientRect(),vc=window.innerHeight/2,ic=r.top+r.height/2,d=Math.abs(ic-vc);
          if(!activeItem){activeItem={item,distance:d};$(item).addClass("no-blur");}
          else if(d<activeItem.distance){$(activeItem.item).removeClass("no-blur");activeItem={item,distance:d};$(item).addClass("no-blur");}
        } else if(activeItem&&activeItem.item===item){$(item).removeClass("no-blur");activeItem=null;}
      }});
    });
  }
};
setupScrollTriggers();
let rt;window.addEventListener("resize",()=>{clearTimeout(rt);rt=setTimeout(setupScrollTriggers,200);});