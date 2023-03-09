/*! For license information please see 98ea13c8.345be669.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[258968],{603905:(e,t,n)=>{n.d(t,{Zo:()=>i,kt:()=>f});var r=n(667294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function p(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var c=r.createContext({}),d=function(e){var t=r.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):p(p({},t),e)),n},i=function(e){var t=d(e.components);return r.createElement(c.Provider,{value:t},e.children)},s="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,c=e.parentName,i=l(e,["components","mdxType","originalType","parentName"]),s=d(n),m=a,f=s["".concat(c,".").concat(m)]||s[m]||u[m]||o;return n?r.createElement(f,p(p({ref:t},i),{},{components:n})):r.createElement(f,p({ref:t},i))}));function f(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,p=new Array(o);p[0]=m;var l={};for(var c in t)hasOwnProperty.call(t,c)&&(l[c]=t[c]);l.originalType=e,l[s]="string"==typeof e?e:a,p[1]=l;for(var d=2;d<o;d++)p[d]=n[d];return r.createElement.apply(null,p)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},469674:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>d,contentTitle:()=>l,default:()=>u,frontMatter:()=>p,metadata:()=>c,toc:()=>i});n(827378);var r=n(603905);function a(){return a=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var n=arguments[t];for(var r in n)Object.prototype.hasOwnProperty.call(n,r)&&(e[r]=n[r])}return e},a.apply(this,arguments)}function o(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}const p={id:"core-components.dependencygraphprops",title:"DependencyGraphProps",description:"API reference for DependencyGraphProps"},l=void 0,c={unversionedId:"reference/core-components.dependencygraphprops",id:"reference/core-components.dependencygraphprops",title:"DependencyGraphProps",description:"API reference for DependencyGraphProps",source:"@site/../docs/reference/core-components.dependencygraphprops.md",sourceDirName:"reference",slug:"/reference/core-components.dependencygraphprops",permalink:"/docs/reference/core-components.dependencygraphprops",draft:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/reference/core-components.dependencygraphprops.md",tags:[],version:"current",frontMatter:{id:"core-components.dependencygraphprops",title:"DependencyGraphProps",description:"API reference for DependencyGraphProps"}},d={},i=[{value:"Remarks",id:"remarks",level:2},{value:"Properties",id:"properties",level:2}],s={toc:i};function u(e){var{components:t}=e,n=o(e,["components"]);return(0,r.kt)("wrapper",a({},s,n,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("p",null,(0,r.kt)("a",a({parentName:"p"},{href:"/docs/reference/"}),"Home")," ",">"," ",(0,r.kt)("a",a({parentName:"p"},{href:"/docs/reference/core-components"}),(0,r.kt)("inlineCode",{parentName:"a"},"@backstage/core-components"))," ",">"," ",(0,r.kt)("a",a({parentName:"p"},{href:"/docs/reference/core-components.dependencygraphprops"}),(0,r.kt)("inlineCode",{parentName:"a"},"DependencyGraphProps"))),(0,r.kt)("p",null,"Properties of ",(0,r.kt)("a",a({parentName:"p"},{href:"/docs/reference/core-components.dependencygraph"}),"DependencyGraph()")),(0,r.kt)("b",null,"Signature:"),(0,r.kt)("pre",null,(0,r.kt)("code",a({parentName:"pre"},{className:"language-typescript"}),"export interface DependencyGraphProps<NodeData, EdgeData> extends React.SVGProps<SVGSVGElement> \n")),(0,r.kt)("b",null,"Extends:")," React.SVGProps<SVGSVGElement>",(0,r.kt)("h2",a({},{id:"remarks"}),"Remarks"),(0,r.kt)("p",null,(0,r.kt)("inlineCode",{parentName:"p"},"<NodeData>")," and ",(0,r.kt)("inlineCode",{parentName:"p"},"<EdgeData>")," are useful when rendering custom or edge labels"),(0,r.kt)("h2",a({},{id:"properties"}),"Properties"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",a({parentName:"tr"},{align:null}),"Property"),(0,r.kt)("th",a({parentName:"tr"},{align:null}),"Modifiers"),(0,r.kt)("th",a({parentName:"tr"},{align:null}),"Type"),(0,r.kt)("th",a({parentName:"tr"},{align:null}),"Description"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.acyclicer"}),"acyclicer?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"'greedy'"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Heuristic used to find set of edges that will make graph acyclic")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.align"}),"align?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.alignment"}),"Alignment")),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Node ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.alignment"}),"alignment"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.curve"}),"curve?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"'curveStepBefore' ","|"," 'curveMonotoneX'"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," A factory for curve generators addressing both lines and areas.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.defs"}),"defs?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"SVGDefsElement ","|"," SVGDefsElement","[","]"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," ",(0,r.kt)("a",a({parentName:"td"},{href:"https://developer.mozilla.org/en-US/docs/Web/SVG/Element/defs"}),"Defs")," shared by rendered SVG to be used by ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.rendernode"}),"DependencyGraphProps.renderNode")," and/or ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.renderlabel"}),"DependencyGraphProps.renderLabel"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.direction"}),"direction?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.direction"}),"Direction")),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Graph ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.direction"}),"direction"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.edgemargin"}),"edgeMargin?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Margin between edges")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.edgeranks"}),"edgeRanks?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Minimum number of ranks to keep between connected nodes")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.edges"}),"edges")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.dependencyedge"}),"DependencyEdge"),"<","EdgeData",">","[","]"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"Edges of graph")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.edgeweight"}),"edgeWeight?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Weight applied to edges in graph")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.fit"}),"fit?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"'grow' ","|"," 'contain'"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Controls if the graph should be contained or grow")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.labeloffset"}),"labelOffset?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," How much to move label away from edge")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.labelposition"}),"labelPosition?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.labelposition"}),"LabelPosition")),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.labelposition"}),"Position")," of label in relation to edge")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.nodemargin"}),"nodeMargin?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Margin between nodes on each rank")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.nodes"}),"nodes")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.dependencynode"}),"DependencyNode"),"<","NodeData",">","[","]"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"Nodes of Graph")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.paddingx"}),"paddingX?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Margin on left and right of whole graph")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.paddingy"}),"paddingY?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Margin on top and bottom of whole graph")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.ranker"}),"ranker?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.ranker"}),"Ranker")),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," ",(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.ranker"}),"Algorithm")," used to rank nodes")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.rankmargin"}),"rankMargin?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"number"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Margin between each rank")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.renderlabel"}),"renderLabel?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.renderlabelfunction"}),"RenderLabelFunction"),"<","EdgeData",">"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Custom label rendering component")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.rendernode"}),"renderNode?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphtypes.rendernodefunction"}),"RenderNodeFunction"),"<","NodeData",">"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Custom node rendering component")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("a",a({parentName:"td"},{href:"/docs/reference/core-components.dependencygraphprops.zoom"}),"zoom?")),(0,r.kt)("td",a({parentName:"tr"},{align:null})),(0,r.kt)("td",a({parentName:"tr"},{align:null}),"'enabled' ","|"," 'disabled' ","|"," 'enable-on-click'"),(0,r.kt)("td",a({parentName:"tr"},{align:null}),(0,r.kt)("i",null,"(Optional)")," Controls zoom behavior of graph")))))}u.isMDXComponent=!0},862525:e=>{var t=Object.getOwnPropertySymbols,n=Object.prototype.hasOwnProperty,r=Object.prototype.propertyIsEnumerable;function a(e){if(null==e)throw new TypeError("Object.assign cannot be called with null or undefined");return Object(e)}e.exports=function(){try{if(!Object.assign)return!1;var e=new String("abc");if(e[5]="de","5"===Object.getOwnPropertyNames(e)[0])return!1;for(var t={},n=0;n<10;n++)t["_"+String.fromCharCode(n)]=n;if("0123456789"!==Object.getOwnPropertyNames(t).map((function(e){return t[e]})).join(""))return!1;var r={};return"abcdefghijklmnopqrst".split("").forEach((function(e){r[e]=e})),"abcdefghijklmnopqrst"===Object.keys(Object.assign({},r)).join("")}catch(a){return!1}}()?Object.assign:function(e,o){for(var p,l,c=a(e),d=1;d<arguments.length;d++){for(var i in p=Object(arguments[d]))n.call(p,i)&&(c[i]=p[i]);if(t){l=t(p);for(var s=0;s<l.length;s++)r.call(p,l[s])&&(c[l[s]]=p[l[s]])}}return c}},541535:(e,t,n)=>{var r=n(862525),a=60103,o=60106;var p=60109,l=60110,c=60112;var d=60115,i=60116;if("function"==typeof Symbol&&Symbol.for){var s=Symbol.for;a=s("react.element"),o=s("react.portal"),s("react.fragment"),s("react.strict_mode"),s("react.profiler"),p=s("react.provider"),l=s("react.context"),c=s("react.forward_ref"),s("react.suspense"),d=s("react.memo"),i=s("react.lazy")}var u="function"==typeof Symbol&&Symbol.iterator;function m(e){for(var t="https://reactjs.org/docs/error-decoder.html?invariant="+e,n=1;n<arguments.length;n++)t+="&args[]="+encodeURIComponent(arguments[n]);return"Minified React error #"+e+"; visit "+t+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}var f={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},g={};function k(e,t,n){this.props=e,this.context=t,this.refs=g,this.updater=n||f}function y(){}function h(e,t,n){this.props=e,this.context=t,this.refs=g,this.updater=n||f}k.prototype.isReactComponent={},k.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error(m(85));this.updater.enqueueSetState(this,e,t,"setState")},k.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},y.prototype=k.prototype;var N=h.prototype=new y;N.constructor=h,r(N,k.prototype),N.isPureReactComponent=!0;var b={current:null},v=Object.prototype.hasOwnProperty,O={key:!0,ref:!0,__self:!0,__source:!0};function w(e,t,n){var r,o={},p=null,l=null;if(null!=t)for(r in void 0!==t.ref&&(l=t.ref),void 0!==t.key&&(p=""+t.key),t)v.call(t,r)&&!O.hasOwnProperty(r)&&(o[r]=t[r]);var c=arguments.length-2;if(1===c)o.children=n;else if(1<c){for(var d=Array(c),i=0;i<c;i++)d[i]=arguments[i+2];o.children=d}if(e&&e.defaultProps)for(r in c=e.defaultProps)void 0===o[r]&&(o[r]=c[r]);return{$$typeof:a,type:e,key:p,ref:l,props:o,_owner:b.current}}function j(e){return"object"==typeof e&&null!==e&&e.$$typeof===a}var P=/\/+/g;function S(e,t){return"object"==typeof e&&null!==e&&null!=e.key?function(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,(function(e){return t[e]}))}(""+e.key):t.toString(36)}function D(e,t,n,r,p){var l=typeof e;"undefined"!==l&&"boolean"!==l||(e=null);var c=!1;if(null===e)c=!0;else switch(l){case"string":case"number":c=!0;break;case"object":switch(e.$$typeof){case a:case o:c=!0}}if(c)return p=p(c=e),e=""===r?"."+S(c,0):r,Array.isArray(p)?(n="",null!=e&&(n=e.replace(P,"$&/")+"/"),D(p,t,n,"",(function(e){return e}))):null!=p&&(j(p)&&(p=function(e,t){return{$$typeof:a,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}(p,n+(!p.key||c&&c.key===p.key?"":(""+p.key).replace(P,"$&/")+"/")+e)),t.push(p)),1;if(c=0,r=""===r?".":r+":",Array.isArray(e))for(var d=0;d<e.length;d++){var i=r+S(l=e[d],d);c+=D(l,t,n,i,p)}else if(i=function(e){return null===e||"object"!=typeof e?null:"function"==typeof(e=u&&e[u]||e["@@iterator"])?e:null}(e),"function"==typeof i)for(e=i.call(e),d=0;!(l=e.next()).done;)c+=D(l=l.value,t,n,i=r+S(l,d++),p);else if("object"===l)throw t=""+e,Error(m(31,"[object Object]"===t?"object with keys {"+Object.keys(e).join(", ")+"}":t));return c}function E(e,t,n){if(null==e)return e;var r=[],a=0;return D(e,r,"","",(function(e){return t.call(n,e,a++)})),r}function _(e){if(-1===e._status){var t=e._result;t=t(),e._status=0,e._result=t,t.then((function(t){0===e._status&&(t=t.default,e._status=1,e._result=t)}),(function(t){0===e._status&&(e._status=2,e._result=t)}))}if(1===e._status)return e._result;throw e._result}var G={current:null};function x(){var e=G.current;if(null===e)throw Error(m(321));return e}},827378:(e,t,n)=>{n(541535)}}]);