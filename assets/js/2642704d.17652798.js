/*! For license information please see 2642704d.17652798.js.LICENSE.txt */
"use strict";(self.webpackChunkbackstage_microsite=self.webpackChunkbackstage_microsite||[]).push([[564197],{603905:(e,t,r)=>{r.d(t,{Zo:()=>l,kt:()=>y});var n=r(667294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function a(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var p=n.createContext({}),c=function(e){var t=n.useContext(p),r=t;return e&&(r="function"==typeof e?e(t):a(a({},t),e)),r},l=function(e){var t=c(e.components);return n.createElement(p.Provider,{value:t},e.children)},u="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},d=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,i=e.originalType,p=e.parentName,l=s(e,["components","mdxType","originalType","parentName"]),u=c(r),d=o,y=u["".concat(p,".").concat(d)]||u[d]||f[d]||i;return r?n.createElement(y,a(a({ref:t},l),{},{components:r})):n.createElement(y,a({ref:t},l))}));function y(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=r.length,a=new Array(i);a[0]=d;var s={};for(var p in t)hasOwnProperty.call(t,p)&&(s[p]=t[p]);s.originalType=e,s[u]="string"==typeof e?e:o,a[1]=s;for(var c=2;c<i;c++)a[c]=r[c];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}d.displayName="MDXCreateElement"},811617:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>c,contentTitle:()=>s,default:()=>f,frontMatter:()=>a,metadata:()=>p,toc:()=>l});r(827378);var n=r(603905);function o(){return o=Object.assign||function(e){for(var t=1;t<arguments.length;t++){var r=arguments[t];for(var n in r)Object.prototype.hasOwnProperty.call(r,n)&&(e[n]=r[n])}return e},o.apply(this,arguments)}function i(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}const a={id:"test-utils.testapiprovider",title:"TestApiProvider",description:"API reference for TestApiProvider"},s=void 0,p={unversionedId:"reference/test-utils.testapiprovider",id:"reference/test-utils.testapiprovider",title:"TestApiProvider",description:"API reference for TestApiProvider",source:"@site/../docs/reference/test-utils.testapiprovider.md",sourceDirName:"reference",slug:"/reference/test-utils.testapiprovider",permalink:"/docs/reference/test-utils.testapiprovider",draft:!1,editUrl:"https://github.com/backstage/backstage/edit/master/docs/../docs/reference/test-utils.testapiprovider.md",tags:[],version:"current",frontMatter:{id:"test-utils.testapiprovider",title:"TestApiProvider",description:"API reference for TestApiProvider"}},c={},l=[{value:"Remarks",id:"remarks",level:2}],u={toc:l};function f(e){var{components:t}=e,r=i(e,["components"]);return(0,n.kt)("wrapper",o({},u,r,{components:t,mdxType:"MDXLayout"}),(0,n.kt)("p",null,(0,n.kt)("a",o({parentName:"p"},{href:"/docs/reference/"}),"Home")," ",">"," ",(0,n.kt)("a",o({parentName:"p"},{href:"/docs/reference/test-utils"}),(0,n.kt)("inlineCode",{parentName:"a"},"@backstage/test-utils"))," ",">"," ",(0,n.kt)("a",o({parentName:"p"},{href:"/docs/reference/test-utils.testapiprovider"}),(0,n.kt)("inlineCode",{parentName:"a"},"TestApiProvider"))),(0,n.kt)("p",null,"The ",(0,n.kt)("inlineCode",{parentName:"p"},"TestApiProvider")," is a Utility API context provider that is particularly well suited for development and test environments such as unit tests, storybooks, and isolated plugin development setups."),(0,n.kt)("p",null,"It lets you provide any number of API implementations, without necessarily having to fully implement each of the APIs."),(0,n.kt)("b",null,"Signature:"),(0,n.kt)("pre",null,(0,n.kt)("code",o({parentName:"pre"},{className:"language-typescript"}),"TestApiProvider: <T extends any[]>(props: TestApiProviderProps<T>) => JSX.Element\n")),(0,n.kt)("h2",o({},{id:"remarks"}),"Remarks"),(0,n.kt)("p",null,"todo: remove this remark tag and ship in the api-reference. There's some odd formatting going on when this is made into a markdown doc, that there's no line break between the emmited ",(0,n.kt)("p",null," for To the following ")," so what happens is that when parsing in docusaurus, it thinks that the code block is mdx rather than a code snippet. Just ommiting this from the report for now until we can work out how to fix laterr. A migration from ",(0,n.kt)("inlineCode",{parentName:"p"},"ApiRegistry")," and ",(0,n.kt)("inlineCode",{parentName:"p"},"ApiProvider")," might look like this, from:"),(0,n.kt)("pre",null,(0,n.kt)("code",o({parentName:"pre"},{className:"language-tsx"}),"renderInTestApp(\n  <ApiProvider\n    apis={ApiRegistry.from([\n      [identityApiRef, mockIdentityApi as unknown as IdentityApi]\n    ])}\n  >\n   ...\n  </ApiProvider>\n)\n")),(0,n.kt)("p",null,"To the following:"),(0,n.kt)("pre",null,(0,n.kt)("code",o({parentName:"pre"},{className:"language-tsx"}),"renderInTestApp(\n  <TestApiProvider apis={[[identityApiRef, mockIdentityApi]]}>\n    ...\n  </TestApiProvider>\n)\n")),(0,n.kt)("p",null,"Note that the cast to ",(0,n.kt)("inlineCode",{parentName:"p"},"IdentityApi")," is no longer needed as long as the mock API implements a subset of the ",(0,n.kt)("inlineCode",{parentName:"p"},"IdentityApi"),"."))}f.isMDXComponent=!0},862525:e=>{var t=Object.getOwnPropertySymbols,r=Object.prototype.hasOwnProperty,n=Object.prototype.propertyIsEnumerable;function o(e){if(null==e)throw new TypeError("Object.assign cannot be called with null or undefined");return Object(e)}e.exports=function(){try{if(!Object.assign)return!1;var e=new String("abc");if(e[5]="de","5"===Object.getOwnPropertyNames(e)[0])return!1;for(var t={},r=0;r<10;r++)t["_"+String.fromCharCode(r)]=r;if("0123456789"!==Object.getOwnPropertyNames(t).map((function(e){return t[e]})).join(""))return!1;var n={};return"abcdefghijklmnopqrst".split("").forEach((function(e){n[e]=e})),"abcdefghijklmnopqrst"===Object.keys(Object.assign({},n)).join("")}catch(o){return!1}}()?Object.assign:function(e,i){for(var a,s,p=o(e),c=1;c<arguments.length;c++){for(var l in a=Object(arguments[c]))r.call(a,l)&&(p[l]=a[l]);if(t){s=t(a);for(var u=0;u<s.length;u++)n.call(a,s[u])&&(p[s[u]]=a[s[u]])}}return p}},541535:(e,t,r)=>{var n=r(862525),o=60103,i=60106;var a=60109,s=60110,p=60112;var c=60115,l=60116;if("function"==typeof Symbol&&Symbol.for){var u=Symbol.for;o=u("react.element"),i=u("react.portal"),u("react.fragment"),u("react.strict_mode"),u("react.profiler"),a=u("react.provider"),s=u("react.context"),p=u("react.forward_ref"),u("react.suspense"),c=u("react.memo"),l=u("react.lazy")}var f="function"==typeof Symbol&&Symbol.iterator;function d(e){for(var t="https://reactjs.org/docs/error-decoder.html?invariant="+e,r=1;r<arguments.length;r++)t+="&args[]="+encodeURIComponent(arguments[r]);return"Minified React error #"+e+"; visit "+t+" for the full message or use the non-minified dev environment for full errors and additional helpful warnings."}var y={isMounted:function(){return!1},enqueueForceUpdate:function(){},enqueueReplaceState:function(){},enqueueSetState:function(){}},m={};function h(e,t,r){this.props=e,this.context=t,this.refs=m,this.updater=r||y}function v(){}function b(e,t,r){this.props=e,this.context=t,this.refs=m,this.updater=r||y}h.prototype.isReactComponent={},h.prototype.setState=function(e,t){if("object"!=typeof e&&"function"!=typeof e&&null!=e)throw Error(d(85));this.updater.enqueueSetState(this,e,t,"setState")},h.prototype.forceUpdate=function(e){this.updater.enqueueForceUpdate(this,e,"forceUpdate")},v.prototype=h.prototype;var g=b.prototype=new v;g.constructor=b,n(g,h.prototype),g.isPureReactComponent=!0;var k={current:null},O=Object.prototype.hasOwnProperty,w={key:!0,ref:!0,__self:!0,__source:!0};function j(e,t,r){var n,i={},a=null,s=null;if(null!=t)for(n in void 0!==t.ref&&(s=t.ref),void 0!==t.key&&(a=""+t.key),t)O.call(t,n)&&!w.hasOwnProperty(n)&&(i[n]=t[n]);var p=arguments.length-2;if(1===p)i.children=r;else if(1<p){for(var c=Array(p),l=0;l<p;l++)c[l]=arguments[l+2];i.children=c}if(e&&e.defaultProps)for(n in p=e.defaultProps)void 0===i[n]&&(i[n]=p[n]);return{$$typeof:o,type:e,key:a,ref:s,props:i,_owner:k.current}}function P(e){return"object"==typeof e&&null!==e&&e.$$typeof===o}var A=/\/+/g;function T(e,t){return"object"==typeof e&&null!==e&&null!=e.key?function(e){var t={"=":"=0",":":"=2"};return"$"+e.replace(/[=:]/g,(function(e){return t[e]}))}(""+e.key):t.toString(36)}function _(e,t,r,n,a){var s=typeof e;"undefined"!==s&&"boolean"!==s||(e=null);var p=!1;if(null===e)p=!0;else switch(s){case"string":case"number":p=!0;break;case"object":switch(e.$$typeof){case o:case i:p=!0}}if(p)return a=a(p=e),e=""===n?"."+T(p,0):n,Array.isArray(a)?(r="",null!=e&&(r=e.replace(A,"$&/")+"/"),_(a,t,r,"",(function(e){return e}))):null!=a&&(P(a)&&(a=function(e,t){return{$$typeof:o,type:e.type,key:t,ref:e.ref,props:e.props,_owner:e._owner}}(a,r+(!a.key||p&&p.key===a.key?"":(""+a.key).replace(A,"$&/")+"/")+e)),t.push(a)),1;if(p=0,n=""===n?".":n+":",Array.isArray(e))for(var c=0;c<e.length;c++){var l=n+T(s=e[c],c);p+=_(s,t,r,l,a)}else if(l=function(e){return null===e||"object"!=typeof e?null:"function"==typeof(e=f&&e[f]||e["@@iterator"])?e:null}(e),"function"==typeof l)for(e=l.call(e),c=0;!(s=e.next()).done;)p+=_(s=s.value,t,r,l=n+T(s,c++),a);else if("object"===s)throw t=""+e,Error(d(31,"[object Object]"===t?"object with keys {"+Object.keys(e).join(", ")+"}":t));return p}function S(e,t,r){if(null==e)return e;var n=[],o=0;return _(e,n,"","",(function(e){return t.call(r,e,o++)})),n}function N(e){if(-1===e._status){var t=e._result;t=t(),e._status=0,e._result=t,t.then((function(t){0===e._status&&(t=t.default,e._status=1,e._result=t)}),(function(t){0===e._status&&(e._status=2,e._result=t)}))}if(1===e._status)return e._result;throw e._result}var x={current:null};function I(){var e=x.current;if(null===e)throw Error(d(321));return e}},827378:(e,t,r)=>{r(541535)}}]);