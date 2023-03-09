/*! For license information please see 3a5f09a3.06f1b805.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[86884],{603905:(t,e,r)=>{r.d(e,{Zo:()=>u,kt:()=>y});var n=r(667294);function i(t,e,r){return e in t?Object.defineProperty(t,e,{value:r,enumerable:!0,configurable:!0,writable:!0}):t[e]=r,t}function c(t,e){var r=Object.keys(t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(t);e&&(n=n.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),r.push.apply(r,n)}return r}function a(t){for(var e=1;e<arguments.length;e++){var r=null!=arguments[e]?arguments[e]:{};e%2?c(Object(r),!0).forEach((function(e){i(t,e,r[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(r)):c(Object(r)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(r,e))}))}return t}function o(t,e){if(null==t)return{};var r,n,i=function(t,e){if(null==t)return{};var r,n,i={},c=Object.keys(t);for(n=0;n<c.length;n++)r=c[n],e.indexOf(r)>=0||(i[r]=t[r]);return i}(t,e);if(Object.getOwnPropertySymbols){var c=Object.getOwnPropertySymbols(t);for(n=0;n<c.length;n++)r=c[n],e.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(t,r)&&(i[r]=t[r])}return i}var s=n.createContext({}),l=function(t){var e=n.useContext(s),r=e;return t&&(r="function"==typeof t?t(e):a(a({},e),t)),r},u=function(t){var e=l(t.components);return n.createElement(s.Provider,{value:e},t.children)},p="mdxType",f={inlineCode:"code",wrapper:function(t){var e=t.children;return n.createElement(n.Fragment,{},e)}},d=n.forwardRef((function(t,e){var r=t.components,i=t.mdxType,c=t.originalType,s=t.parentName,u=o(t,["components","mdxType","originalType","parentName"]),p=l(r),d=i,y=p["".concat(s,".").concat(d)]||p[d]||f[d]||c;return r?n.createElement(y,a(a({ref:e},u),{},{components:r})):n.createElement(y,a({ref:e},u))}));function y(t,e){var r=arguments,i=e&&e.mdxType;if("string"==typeof t||i){var c=r.length,a=new Array(c);a[0]=d;var o={};for(var s in e)hasOwnProperty.call(e,s)&&(o[s]=e[s]);o.originalType=t,o[p]="string"==typeof t?t:i,a[1]=o;for(var l=2;l<c;l++)a[l]=r[l];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},735821:(t,e,r)=>{r.r(e),r.d(e,{assets:()=>l,contentTitle:()=>o,default:()=>f,frontMatter:()=>a,metadata:()=>s,toc:()=>u});r(827378);var n=r(603905);function i(){return i=Object.assign||function(t){for(var e=1;e<arguments.length;e++){var r=arguments[e];for(var n in r)Object.prototype.hasOwnProperty.call(r,n)&&(t[n]=r[n])}return t},i.apply(this,arguments)}function c(t,e){if(null==t)return{};var r,n,i=function(t,e){if(null==t)return{};var r,n,i={},c=Object.keys(t);for(n=0;n<c.length;n++)r=c[n],e.indexOf(r)>=0||(i[r]=t[r]);return i}(t,e);if(Object.getOwnPropertySymbols){var c=Object.getOwnPropertySymbols(t);for(n=0;n<c.length;n++)r=c[n],e.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(t,r)&&(i[r]=t[r])}return i}const a={id:"plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",title:"CicdStatisticsApi.fetchBuilds()",description:"API reference for CicdStatisticsApi.fetchBuilds()"},o=void 0,s={unversionedId:"reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",id:"reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",title:"CicdStatisticsApi.fetchBuilds()",description:"API reference for CicdStatisticsApi.fetchBuilds()",source:"@site/../docs/reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds.md",sourceDirName:"reference",slug:"/reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",permalink:"/docs/reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",draft:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds.md",tags:[],version:"current",frontMatter:{id:"plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds",title:"CicdStatisticsApi.fetchBuilds()",description:"API reference for CicdStatisticsApi.fetchBuilds()"}},l={},u=[{value:"Parameters",id:"parameters",level:2}],p={toc:u};function f(t){var{components:e}=t,r=c(t,["components"]);return(0,n.kt)("wrapper",i({},p,r,{components:e,mdxType:"MDXLayout"}),(0,n.kt)("p",null,(0,n.kt)("a",i({parentName:"p"},{href:"/docs/reference/"}),"Home")," ",">"," ",(0,n.kt)("a",i({parentName:"p"},{href:"/docs/reference/plugin-cicd-statistics"}),(0,n.kt)("inlineCode",{parentName:"a"},"@backstage/plugin-cicd-statistics"))," ",">"," ",(0,n.kt)("a",i({parentName:"p"},{href:"/docs/reference/plugin-cicd-statistics.cicdstatisticsapi"}),(0,n.kt)("inlineCode",{parentName:"a"},"CicdStatisticsApi"))," ",">"," ",(0,n.kt)("a",i({parentName:"p"},{href:"/docs/reference/plugin-cicd-statistics.cicdstatisticsapi.fetchbuilds"}),(0,n.kt)("inlineCode",{parentName:"a"},"fetchBuilds"))),(0,n.kt)("b",null,"Signature:"),(0,n.kt)("pre",null,(0,n.kt)("code",i({parentName:"pre"},{className:"language-typescript"}),"fetchBuilds(options: FetchBuildsOptions): Promise<CicdState>;\n")),(0,n.kt)("h2",i({},{id:"parameters"}),"Parameters"),(0,n.kt)("table",null,(0,n.kt)("thead",{parentName:"table"},(0,n.kt)("tr",{parentName:"thead"},(0,n.kt)("th",i({parentName:"tr"},{align:null}),"Parameter"),(0,n.kt)("th",i({parentName:"tr"},{align:null}),"Type"),(0,n.kt)("th",i({parentName:"tr"},{align:null}),"Description"))),(0,n.kt)("tbody",{parentName:"table"},(0,n.kt)("tr",{parentName:"tbody"},(0,n.kt)("td",i({parentName:"tr"},{align:null}),"options"),(0,n.kt)("td",i({parentName:"tr"},{align:null}),(0,n.kt)("a",i({parentName:"td"},{href:"/docs/reference/plugin-cicd-statistics.fetchbuildsoptions"}),"FetchBuildsOptions")),(0,n.kt)("td",i({parentName:"tr"},{align:null}))))),(0,n.kt)("b",null,"Returns:"),(0,n.kt)("p",null,"Promise","<",(0,n.kt)("a",i({parentName:"p"},{href:"/docs/reference/plugin-cicd-statistics.cicdstate"}),"CicdState"),">"))}f.isMDXComponent=!0},862525:t=>{var e=Object.getOwnPropertySymbols,r=Object.prototype.hasOwnProperty,n=Object.prototype.propertyIsEnumerable;function i(t){if(null==t)throw new TypeError("Object.assign cannot be called with null or undefined");return Object(t)}t.exports=function(){try{if(!Object.assign)return!1;var t=new String("abc");if(t[5]="de","5"===Object.getOwnPropertyNames(t)[0])return!1;for(var e={},r=0;r<10;r++)e["_"+String.fromCharCode(r)]=r;if("0123456789"!==Object.getOwnPropertyNames(e).map((function(t){return e[t]})).join(""))return!1;var n={};return"abcdefghijklmnopqrst".split("").forEach((function(t){n[t]=t})),"abcdefghijklmnopqrst"===Object.keys(Object.assign({},n)).join("")}catch(i){return!1}}()?Object.assign:function(t,c){for(var a,o,s=i(t),l=1;l<arguments.length;l++){for(var u in a=Object(arguments[l]))r.call(a,u)&&(s[u]=a[u]);if(e){o=e(a);for(var p=0;p<o.length;p++)n.call(a,o[p])&&(s[o[p]]=a[o[p]])}}return s}},541535:(t,e,r)=>{var n=r(862525),i=60103,c=60106;var a=60109,o=60110,s=60112;var l=60115,u=60116;if("function"==typeof Symbol&&Symbol.for){var p=Symbol.for;i=p("react.element"),c=p("react.portal"),p("react.fragment"),p("react.strict_mode"),p("react.profiler"),a=p("react.provider"),o=p("react.context"),s=p("react.forward_ref"),p("react.suspense"),l=p("react.memo"),u=p("react.lazy")}var f="function"==typeof Symbol&&Symbol.iterator;function d(t){for(var e="https://reactjs.org/docs/error-decoder.html?invariant="+t,r=1;r<arguments.length;r++)e+="&args[]="+encodeURIComponent(arguments[r]);return"Minified React error #"+t+"; visit "+e+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}var y={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},m={};function b(t,e,r){this.props=t,this.context=e,this.refs=m,this.updater=r||y}function h(){}function g(t,e,r){this.props=t,this.context=e,this.refs=m,this.updater=r||y}b.prototype.isReactComponent={},b.prototype.setState=function(t,e){if("object"!=typeof t&&"function"!=typeof t&&null!=t)throw Error(d(85));this.updater.enqueueSetState(this,t,e,"setState")},b.prototype.forceUpdate=function(t){this.updater.enqueueForceUpdate(this,t,"forceUpdate")},h.prototype=b.prototype;var v=g.prototype=new h;v.constructor=g,n(v,b.prototype),v.isPureReactComponent=!0;var O={current:null},k=Object.prototype.hasOwnProperty,j={key:!0,ref:!0,__self:!0,__source:!0};function w(t,e,r){var n,c={},a=null,o=null;if(null!=e)for(n in void 0!==e.ref&&(o=e.ref),void 0!==e.key&&(a=""+e.key),e)k.call(e,n)&&!j.hasOwnProperty(n)&&(c[n]=e[n]);var s=arguments.length-2;if(1===s)c.children=r;else if(1<s){for(var l=Array(s),u=0;u<s;u++)l[u]=arguments[u+2];c.children=l}if(t&&t.defaultProps)for(n in s=t.defaultProps)void 0===c[n]&&(c[n]=s[n]);return{$$typeof:i,type:t,key:a,ref:o,props:c,_owner:O.current}}function P(t){return"object"==typeof t&&null!==t&&t.$$typeof===i}var S=/\/+/g;function N(t,e){return"object"==typeof t&&null!==t&&null!=t.key?function(t){var e={"=":"=0",":":"=2"};return"$"+t.replace(/[=:]/g,(function(t){return e[t]}))}(""+t.key):e.toString(36)}function _(t,e,r,n,a){var o=typeof t;"undefined"!==o&&"boolean"!==o||(t=null);var s=!1;if(null===t)s=!0;else switch(o){case"string":case"number":s=!0;break;case"object":switch(t.$$typeof){case i:case c:s=!0}}if(s)return a=a(s=t),t=""===n?"."+N(s,0):n,Array.isArray(a)?(r="",null!=t&&(r=t.replace(S,"$&/")+"/"),_(a,e,r,"",(function(t){return t}))):null!=a&&(P(a)&&(a=function(t,e){return{$$typeof:i,type:t.type,key:e,ref:t.ref,props:t.props,_owner:t._owner}}(a,r+(!a.key||s&&s.key===a.key?"":(""+a.key).replace(S,"$&/")+"/")+t)),e.push(a)),1;if(s=0,n=""===n?".":n+":",Array.isArray(t))for(var l=0;l<t.length;l++){var u=n+N(o=t[l],l);s+=_(o,e,r,u,a)}else if(u=function(t){return null===t||"object"!=typeof t?null:"function"==typeof(t=f&&t[f]||t["@@iterator"])?t:null}(t),"function"==typeof u)for(t=u.call(t),l=0;!(o=t.next()).done;)s+=_(o=o.value,e,r,u=n+N(o,l++),a);else if("object"===o)throw e=""+t,Error(d(31,"[object Object]"===e?"object with keys {"+Object.keys(t).join(", ")+"}":e));return s}function C(t,e,r){if(null==t)return t;var n=[],i=0;return _(t,n,"","",(function(t){return e.call(r,t,i++)})),n}function E(t){if(-1===t._status){var e=t._result;e=e(),t._status=0,t._result=e,e.then((function(e){0===t._status&&(e=e.default,t._status=1,t._result=e)}),(function(e){0===t._status&&(t._status=2,t._result=e)}))}if(1===t._status)return t._result;throw t._result}var x={current:null};function A(){var t=x.current;if(null===t)throw Error(d(321));return t}},827378:(t,e,r)=>{r(541535)}}]);