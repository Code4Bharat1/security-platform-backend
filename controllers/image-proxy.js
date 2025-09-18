export default async function handler(req, res) {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).send("No URL provided");

    const response = await fetch(url);
    if (!response.ok) throw new Error("Failed to fetch image");

    const buffer = await response.arrayBuffer();
    const contentType = response.headers.get("content-type") || "image/jpeg";

    res.setHeader("Content-Type", contentType);
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("Image proxy error:", err);
    // Fallback image
    res.redirect("https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVlzRvr9tBHSRQqe_2jj8SrExmcCFhoLUrrMI4GzbM0-GggNMW0BTO02GXh8i_ShmsUpEJyy85FIPBXIbXwMjR68D30ldhn8osa8zG-wKqJu6KDR3Kuri6sd9GXMbhyannAnOJEQMY4tsxJ26pXPujtzzC-8U-kncd-YNj6LfRgiETNHccmSwQQY0zh3gQ/s1600/chrome.png");
  }
}
