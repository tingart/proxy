app.all("/proxy", async (req, res) => {
  const url = req.query.url;

  if (!url) {
    return res.status(400).send("Missing url");
  }

  try {
    new URL(url);
  } catch {
    return res.status(400).send("Invalid url");
  }

  let sid = req.query.sid;

  if (!sid || !sessions.has(sid)) {
    sid = token();
    sessions.set(sid, {
      target: url,
      cookie: ""
    });
  }

  await handleProxy(req, res, url, sid);
});
