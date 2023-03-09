/*! For license information please see 7a8e5aa3.cf44e5d9.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[787129],{603905:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>d});var a=n(667294);function r(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){r(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}var l=a.createContext({}),c=function(e){var t=a.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=c(e.components);return a.createElement(l.Provider,{value:t},e.children)},u="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},f=a.forwardRef((function(e,t){var n=e.components,r=e.mdxType,o=e.originalType,l=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),u=c(n),f=r,d=u["".concat(l,".").concat(f)]||u[f]||m[f]||o;return n?a.createElement(d,i(i({ref:t},p),{},{components:n})):a.createElement(d,i({ref:t},p))}));function d(e,t){var n=arguments,r=t&&t.mdxType;if("string"==typeof e||r){var o=n.length,i=new Array(o);i[0]=f;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[u]="string"==typeof e?e:r,i[1]=s;for(var c=2;c<o;c++)i[c]=n[c];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}f.displayName="MDXCreateElement"},828326:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>s,default:()=>m,frontMatter:()=>i,metadata:()=>l,toc:()=>p});n(827378);var a=n(603905);function r(){return r=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var a in n)Object.prototype.hasOwnProperty.call(n,a)&&(e[a]=n[a])}return e},r.apply(this,arguments)}function o(e,t){if(null==e)return{};var n,a,r=function(e,t){if(null==e)return{};var n,a,r={},o=Object.keys(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||(r[n]=e[n]);return r}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(a=0;a<o.length;a++)n=o[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(r[n]=e[n])}return r}const i={id:"adopting",title:"Strategies for adopting",description:"Documentation on some general best practices that have been key to Backstage's success inside Spotify"},s=void 0,l={unversionedId:"overview/adopting",id:"overview/adopting",title:"Strategies for adopting",description:"Documentation on some general best practices that have been key to Backstage's success inside Spotify",source:"@site/../docs/overview/adopting.md",sourceDirName:"overview",slug:"/overview/adopting",permalink:"/docs/overview/adopting",draft:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/overview/adopting.md",tags:[],version:"current",frontMatter:{id:"adopting",title:"Strategies for adopting",description:"Documentation on some general best practices that have been key to Backstage's success inside Spotify"},sidebar:"docs",previous:{title:"The Spotify Story",permalink:"/docs/overview/background"},next:{title:"Release & Versioning Policy",permalink:"/docs/overview/versioning-policy"}},c={},p=[{value:"Organizational setup",id:"organizational-setup",level:2},{value:"Internal evangelization",id:"internal-evangelization",level:2},{value:"Tactics",id:"tactics",level:3},{value:"KPIs and metrics",id:"kpis-and-metrics",level:2}],u={toc:p};function m(e){var{components:t}=e,i=o(e,["components"]);return(0,a.kt)("wrapper",r({},u,i,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"This document outlines some general best practices that have been key to\nBackstage's success inside Spotify. Every organization is different and some of\nthese learnings will therefore not be applicable for your company. We are hoping\nthat this can become a living document, and strongly encourage you to contribute\nback whatever learnings you gather while adopting Backstage inside your company."),(0,a.kt)("h2",r({},{id:"organizational-setup"}),"Organizational setup"),(0,a.kt)("p",null,"The true value of Backstage is unlocked when it becomes ",(0,a.kt)("em",{parentName:"p"},"THE")," developer portal\nat your company. As such it is important to recognize that you will need a\ncentral team that owns your Backstage deployment and treats it like a product."),(0,a.kt)("p",null,"This team will have ",(0,a.kt)("strong",{parentName:"p"},"four")," primary objectives:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Maintain and operate your deployment of Backstage. This includes customer\nsupport, infrastructure, CI/CD and, as your Backstage product grows, on-call\nsupport.")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Drive adoption of customers (developers at your company).")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Work with senior tech leadership and architects to ensure your organization's\nbest practices for software development are encoded into a set of\n",(0,a.kt)("a",r({parentName:"p"},{href:"/docs/features/software-templates/"}),"Software Templates"),".")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Evangelize Backstage as a central platform towards other\ninfrastructure/platform teams."))),(0,a.kt)("h2",r({},{id:"internal-evangelization"}),"Internal evangelization"),(0,a.kt)("p",null,'The last objective deserves more attention, since it is the least obvious, but\nalso the most critical to successfully creating a consolidated platform. When\ndone right, Backstage acts as a "platform of platforms" or marketplace between\ninfra/platform teams and end-users:'),(0,a.kt)("p",null,(0,a.kt)("img",{alt:"pop",src:n(480097).Z,width:"1180",height:"660"})),(0,a.kt)("p",null,"While anyone at your company can contribute to the platform, the vast majority\nof work will be done by teams that also have internal engineers as their\ncustomers. The central team should treat these ",(0,a.kt)("em",{parentName:"p"},"contributing teams")," as customers\nof the platform as well."),(0,a.kt)("p",null,"These teams should be able to autonomously deliver value directly to their\ncustomers. This is done primarily by building ",(0,a.kt)("a",r({parentName:"p"},{href:"/docs/plugins/"}),"plugins"),".\nContributing teams should themselves treat their plugins as, or part of, the\nproducts they maintain."),(0,a.kt)("blockquote",null,(0,a.kt)("p",{parentName:"blockquote"},"Case study: Inside Spotify we have a team that owns our CI platform. They not\nonly maintain the pipelines and build servers, but also expose their product\nin Backstage through a plugin. Since they also\n",(0,a.kt)("a",r({parentName:"p"},{href:"/docs/plugins/call-existing-api"}),"maintain their own API"),", they can improve\ntheir product by iterating on API and UI in lockstep. Because the plugin\nfollows our ",(0,a.kt)("a",r({parentName:"p"},{href:"/docs/dls/design"}),"platform design guidelines")," their customers get\na CI experience that is consistent with other tools on the platform (and users\ndon't have to become experts in Jenkins).")),(0,a.kt)("h3",r({},{id:"tactics"}),"Tactics"),(0,a.kt)("p",null,"Examples of tactics we have used to evangelize Backstage internally:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},'Arrange "Lunch & Learns" and seminars. Frequently offer teams interested in\nBackstage development to come to a seminar where you show, for example, how to\nbuild a plugin from scratch.')),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},'Embedding. As contributing teams start development of their first plugin it is\noften very appreciated to have one person from the central team come over and\n"embed" for a Sprint or two.')),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Hack days. Backstage-focused Hackathons or hack days is a fun way to get\npeople into plugin development.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Show & tell meetings. In order to build an internal community around Backstage\nwe have quarterly meetings where anyone working on Backstage is invited to\npresent their work. This is not only a great way to get early feedback, but\nalso helps coordination between teams that are building overlapping\nexperiences.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Provide metrics. Add instrumentation to your Backstage deployment and make\nmetrics available to contributing teams. At Spotify, we have even gone so far\nas to send out weekly digest emails showing how usage metrics have changed for\nindividual plugins.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Pro-actively identify new plugins. Reach out to teams that own internal UIs or\nplatforms that you think would make sense to consolidate into Backstage."))),(0,a.kt)("h2",r({},{id:"kpis-and-metrics"}),"KPIs and metrics"),(0,a.kt)("p",null,"These are some of the metrics that you can use to verify if Backstage has a\nsuccessful impact on your software development process:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"Onboarding time")," Time until new engineers are productive. At Spotify we\nmeasure this as the time until the employee has merged their 10th PR (this\nmetric was down 55% two years after deploying Backstage). Even though you may\nnot be onboarding engineers at a rapid pace, this metric is a great proxy for\nthe overall complexity of your ecosystem. Reducing it will therefore benefit\nyour whole engineering organization, not just new joiners.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"Number of merges per developer/day")," Less time spent jumping between\ndifferent tools and looking for information means more time to focus on\nshipping code. A second level of bottlenecks can be identified if you\ncategorize contributions by domain (services, web, data, etc).")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"Deploys to production")," Cousin to the metric above: How many times does an\nengineer push changes into production.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"MTTR")," With clear ownership of all the pieces in your microservices\necosystem and all tools integrated into one place, Backstage makes it quicker\nfor teams to find the root cause of failures, and fix them.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"Context switching"),' Reducing context switching can help engineers stay in\nthe "zone". We measure the number of different tools an engineer has to\ninteract with in order to get a certain job done (e.g. push a change, follow\nit into production and validate it did not break anything).')),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"T-shapedness")," A\n",(0,a.kt)("a",r({parentName:"p"},{href:"https://medium.com/@jchyip/why-t-shaped-people-e8706198e437"}),"T-shaped"),"\nengineer is someone that is able to contribute to different domains of\nengineering. Teams with T-shaped people have fewer bottlenecks and can\ntherefore deliver more consistently. Backstage makes it easier to be T-shaped\nsince tools and infrastructure are consistent between domains, and information\nis available centrally.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"eNPS")," Surveys asking about how productive people feel, how easy it is to\nfind information and overall satisfaction with internal tools.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},(0,a.kt)("strong",{parentName:"p"},"Fragmentation")," ",(0,a.kt)("em",{parentName:"p"},"(Experimental)")," Backstage\n",(0,a.kt)("a",r({parentName:"p"},{href:"/docs/features/software-templates/"}),"Software Templates")," help drive\nstandardization in your software ecosystem. By measuring the variance in\ntechnology between different software components it is possible to get a sense\nof the overall fragmentation in your ecosystem. Examples could include:\nframework versions, languages, deployment methods and various code quality\nmeasurements."))),(0,a.kt)("p",null,"Additionally, these proxy metrics can be used to validate the success of\nBackstage as ",(0,a.kt)("em",{parentName:"p"},"the")," platform:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Nr of teams that have contributed at least one plugin (currently 63 inside\nSpotify)")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Nr of total plugins (currently 135 inside Spotify)")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"% of contributions coming from outside the central Backstage team (currently\n85% inside Spotify)")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Traditional metrics such as visits (MAU, DAU, etc) and page views. Currently\n~50% of all Spotifiers use Backstage on a monthly basis, even though the\npercentage of engineers is below 50%. Most engineers actually use Backstage on\na daily basis."))),(0,a.kt)("p",null,"Again, any feedback is appreciated. Please use the Edit button at the bottom of the\npage to make a suggestion."),(0,a.kt)("p",null,(0,a.kt)("em",{parentName:"p"},(0,a.kt)("strong",{parentName:"em"},"Note!"),' It might be tempting to try to optimize Backstage usage and\n"engagement". Even though you want to consolidate all your tooling and technical\ndocumentation in Backstage, it is important to remember that time spent in\nBackstage is time not spent writing code')," \ud83d\ude43"))}m.isMDXComponent=!0},480097:(e,t,n)=>{n.d(t,{Z:()=>a});const a=n.p+"assets/images/pop-347af6a9b37c1529dbef0fa692798aad.png"},862525:e=>{var t=Object.getOwnPropertySymbols,n=Object.prototype.hasOwnProperty,a=Object.prototype.propertyIsEnumerable;function r(e){if(null==e)throw new TypeError("Object.assign cannot be called with null or undefined");return Object(e)}e.exports=function(){try{if(!Object.assign)return!1;var e=new String("abc");if(e[5]="de","5"===Object.getOwnPropertyNames(e)[0])return!1;for(var t={},n=0;n<10;n++)t["_"+String.fromCharCode(n)]=n;if("0123456789"!==Object.getOwnPropertyNames(t).map((function(e){return t[e]})).join(""))return!1;var a={};return"abcdefghijklmnopqrst".split("").forEach((function(e){a[e]=e})),"abcdefghijklmnopqrst"===Object.keys(Object.assign({},a)).join("")}catch(r){return!1}}()?Object.assign:function(e,o){for(var i,s,l=r(e),c=1;c<arguments.length;c++){for(var p in i=Object(arguments[c]))n.call(i,p)&&(l[p]=i[p]);if(t){s=t(i);for(var u=0;u<s.length;u++)a.call(i,s[u])&&(l[s[u]]=i[s[u]])}}return l}},541535:(e,t,n)=>{var a=n(862525),r=60103,o=60106;var i=60109,s=60110,l=60112;var c=60115,p=60116;if("function"==typeof Symbol&&Symbol.for){var u=Symbol.for;r=u("react.element"),o=u("react.portal"),u("react.fragment"),u("react.strict_mode"),u("react.profiler"),i=u("react.provider"),s=u("react.context"),l=u("react.forward_ref"),u("react.suspense"),c=u("react.memo"),p=u("react.lazy")}var m="function"==typeof Symbol&&Symbol.iterator;function f(e){for(var t="https://reactjs.org/docs/error-decoder.html?invariant="+e,n=1;n<arguments.length;n++)t+="&args[]="+encodeURIComponent(arguments[n]);return"Minified React error #"+e+"; visit "+t+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}var d={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},h={};function g(e,t,n){this.props=e,this.context=t,this.refs=h,this.updater=n||d}function y(){}function k(e,t,n){this.props=e,this.context=t,this.refs=h,this.updater=n||d}g.prototype.isReactComponent={},g.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error(f(85));this.updater.enqueueSetState(this,e,t,"setState")},g.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},y.prototype=g.prototype;var v=k.prototype=new y;v.constructor=k,a(v,g.prototype),v.isPureReactComponent=!0;var b={current:null},w=Object.prototype.hasOwnProperty,N={key:!0,ref:!0,__self:!0,__source:!0};function O(e,t,n){var a,o={},i=null,s=null;if(null!=t)for(a in void 0!==t.ref&&(s=t.ref),void 0!==t.key&&(i=""+t.key),t)w.call(t,a)&&!N.hasOwnProperty(a)&&(o[a]=t[a]);var l=arguments.length-2;if(1===l)o.children=n;else if(1<l){for(var c=Array(l),p=0;p<l;p++)c[p]=arguments[p+2];o.children=c}if(e&&e.defaultProps)for(a in l=e.defaultProps)void 0===o[a]&&(o[a]=l[a]);return{$$typeof:r,type:e,key:i,ref:s,props:o,_owner:b.current}}function j(e){return"object"==typeof e&&null!==e&&e.$$typeof===r}var S=/\/+/g;function T(e,t){return"object"==typeof e&&null!==e&&null!=e.key?function(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,(function(e){return t[e]}))}(""+e.key):t.toString(36)}function P(e,t,n,a,i){var s=typeof e;"undefined"!==s&&"boolean"!==s||(e=null);var l=!1;if(null===e)l=!0;else switch(s){case"string":case"number":l=!0;break;case"object":switch(e.$$typeof){case r:case o:l=!0}}if(l)return i=i(l=e),e=""===a?"."+T(l,0):a,Array.isArray(i)?(n="",null!=e&&(n=e.replace(S,"$&/")+"/"),P(i,t,n,"",(function(e){return e}))):null!=i&&(j(i)&&(i=function(e,t){return{$$typeof:r,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}(i,n+(!i.key||l&&l.key===i.key?"":(""+i.key).replace(S,"$&/")+"/")+e)),t.push(i)),1;if(l=0,a=""===a?".":a+":",Array.isArray(e))for(var c=0;c<e.length;c++){var p=a+T(s=e[c],c);l+=P(s,t,n,p,i)}else if(p=function(e){return null===e||"object"!=typeof e?null:"function"==typeof(e=m&&e[m]||e["@@iterator"])?e:null}(e),"function"==typeof p)for(e=p.call(e),c=0;!(s=e.next()).done;)l+=P(s=s.value,t,n,p=a+T(s,c++),i);else if("object"===s)throw t=""+e,Error(f(31,"[object Object]"===t?"object with keys {"+Object.keys(e).join(", ")+"}":t));return l}function B(e,t,n){if(null==e)return e;var a=[],r=0;return P(e,a,"","",(function(e){return t.call(n,e,r++)})),a}function x(e){if(-1===e._status){var t=e._result;t=t(),e._status=0,e._result=t,t.then((function(t){0===e._status&&(t=t.default,e._status=1,e._result=t)}),(function(t){0===e._status&&(e._status=2,e._result=t)}))}if(1===e._status)return e._result;throw e._result}var E={current:null};function _(){var e=E.current;if(null===e)throw Error(f(321));return e}},827378:(e,t,n)=>{n(541535)}}]);