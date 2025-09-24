// pages/api/hacker-news.js (for Next.js 12 and below)
// OR app/api/hacker-news/route.js (for Next.js 13+ App Router)

// For Next.js 13+ App Router
// For Next.js 13+ App Router
export async function GET() {
  try {
    console.log('Fetching news from The Hacker News...');
    
    const rssUrl = 'https://feeds.feedburner.com/TheHackersNews';
    
    const response = await fetch(rssUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/rss+xml, application/xml, text/xml',
        'Cache-Control': 'no-cache'
      },
      next: { revalidate: 0 }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
    }

    const xmlData = await response.text();
    console.log('XML Data length:', xmlData.length);

    const parseXML = (xmlString) => {
      const itemPattern = /<item>([\s\S]*?)<\/item>/g;
      const items = [];
      let match;

      while ((match = itemPattern.exec(xmlString)) !== null) {
        const itemContent = match[1];
        
        // Extract title
        const titleMatch = itemContent.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/);
        const title = titleMatch ? titleMatch[1] : itemContent.match(/<title>(.*?)<\/title>/)?.[1] || 'Untitled';
        
        // Extract link
        const linkMatch = itemContent.match(/<link>(.*?)<\/link>/);
        const link = linkMatch ? linkMatch[1].trim() : 'https://thehackernews.com/';
        
        // Extract description
        const descMatch = itemContent.match(/<description><!\[CDATA\[([\s\S]*?)\]\]><\/description>/);
        let description = descMatch ? descMatch[1] : itemContent.match(/<description>([\s\S]*?)<\/description>/)?.[1] || '';
        
        // Extract publication date
        const pubDateMatch = itemContent.match(/<pubDate>(.*?)<\/pubDate>/);
        const pubDate = pubDateMatch ? pubDateMatch[1] : new Date().toISOString();
        
        // Extract image from enclosure tag (FIXED)
        let imageUrl = "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVlzRvr9tBHSRQqe_2jj8SrExmcCFhoLUrrMI4GzbM0-GggNMW0BTO02GXh8i_ShmsUpEJyy85FIPBXIbXwMjR68D30ldhn8osa8zG-wKqJu6KDR3Kuri6sd9GXMbhyannAnOJEQMY4tsxJ26pXPujtzzC-8U-kncd-YNj6LfRgiETNHccmSwQQY0zh3gQ/s1600/chrome.png";
        const enclosureMatch = itemContent.match(/<enclosure[^>]+url=["']([^"']+)["'][^>]*>/i);
        if (enclosureMatch) {
          imageUrl = enclosureMatch[1];
          console.log('Found enclosure image:', imageUrl);
        } else {
          // Fallback: try to extract from description if enclosure not found
          const imgMatch = description.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
          if (imgMatch) {
            imageUrl = imgMatch[1];
            console.log('Found description image:', imageUrl);
          }
        }
        
        // Clean description
        const cleanDescription = description
          .replace(/<[^>]*>/g, '')
          .replace(/&nbsp;/g, ' ')
          .replace(/&quot;/g, '"')
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .trim()
          .substring(0, 150) + (description.length > 150 ? '...' : '');

        items.push({
          title: title.trim(),
          description: cleanDescription,
          link: link,
          image: imageUrl,
          publishedAt: pubDate,
          source: 'The Hacker News'
        });
      }
      
      return items;
    };

    const articles = parseXML(xmlData);
    console.log('Parsed articles:', articles.length);

    if (articles.length > 0) {
      const latestArticle = articles[0];
      console.log('Latest article:', latestArticle.title);
      console.log('Latest article image:', latestArticle.image);
      
      return Response.json({
        success: true,
        article: latestArticle,
        timestamp: new Date().toISOString(),
        totalArticles: articles.length
      });
    } else {
      throw new Error('No articles found in RSS feed');
    }

  } catch (error) {
    console.error('Error in hacker-news API:', error);
    
    return Response.json({
      success: false,
      error: error.message,
      article: {
        title: "Latest Cybersecurity News",
        description: "Unable to fetch latest news. Stay updated with the latest cybersecurity threats and vulnerabilities by visiting The Hacker News directly.",
        image: "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVlzRvr9tBHSRQqe_2jj8SrExmcCFhoLUrrMI4GzbM0-GggNMW0BTO02GXh8i_ShmsUpEJyy85FIPBXIbXwMjR68D30ldhn8osa8zG-wKqJu6KDR3Kuri6sd9GXMbhyannAnOJEQMY4tsxJ26pXPujtzzC-8U-kncd-YNj6LfRgiETNHccmSwQQY0zh3gQ/s1600/chrome.png",
        link: "https://thehackernews.com/",
        publishedAt: new Date().toISOString(),
        source: 'The Hacker News (Fallback)'
      }
    }, { status: 200 });
  }
}
// For Next.js 12 and below (pages/api/hacker-news.js)
export const blogs = async (req, res) => {
  if (req.method !== 'GET') {
    return res.status(405).json({ 
      success: false, 
      error: 'Method not allowed' 
    });
  }

  try {
    console.log('Fetching news from The Hacker News...');
    
    const rssUrl = 'https://feeds.feedburner.com/TheHackersNews';
    
    const response = await fetch(rssUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/rss+xml, application/xml, text/xml',
        'Cache-Control': 'no-cache'
      }
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status} - ${response.statusText}`);
    }

    const xmlData = await response.text();
    console.log('XML Data received, length:', xmlData.length);

    // Simple XML parsing
    const parseXML = (xmlString) => {
      const itemPattern = /<item>([\s\S]*?)<\/item>/g;
      const items = [];
      let match;

      while ((match = itemPattern.exec(xmlString)) !== null) {
        const itemContent = match[1];
        
        const titleMatch = itemContent.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/);
        const title = titleMatch ? titleMatch[1] : itemContent.match(/<title>(.*?)<\/title>/)?.[1] || 'Untitled';
        
        const linkMatch = itemContent.match(/<link>(.*?)<\/link>/);
        const link = linkMatch ? linkMatch[1].trim() : 'https://thehackernews.com/';
        
        const descMatch = itemContent.match(/<description><!\[CDATA\[([\s\S]*?)\]\]><\/description>/);
        let description = descMatch ? descMatch[1] : itemContent.match(/<description>([\s\S]*?)<\/description>/)?.[1] || '';
        
        const pubDateMatch = itemContent.match(/<pubDate>(.*?)<\/pubDate>/);
        const pubDate = pubDateMatch ? pubDateMatch[1] : new Date().toISOString();
        
        let imageUrl = "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVlzRvr9tBHSRQqe_2jj8SrExmcCFhoLUrrMI4GzbM0-GggNMW0BTO02GXh8i_ShmsUpEJyy85FIPBXIbXwMjR68D30ldhn8osa8zG-wKqJu6KDR3Kuri6sd9GXMbhyannAnOJEQMY4tsxJ26pXPujtzzC-8U-kncd-YNj6LfRgiETNHccmSwQQY0zh3gQ/s1600/chrome.png";
        const imgMatch = description.match(/<img[^>]+src=["']([^"']+)["'][^>]*>/i);
        if (imgMatch) {
          imageUrl = imgMatch[1];
        }
        
        const cleanDescription = description
          .replace(/<[^>]*>/g, '')
          .replace(/&nbsp;/g, ' ')
          .replace(/&quot;/g, '"')
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .trim()
          .substring(0, 150) + (description.length > 150 ? '...' : '');

        items.push({
          title: title.trim(),
          description: cleanDescription,
          link: link,
          image: imageUrl,
          publishedAt: pubDate,
          source: 'The Hacker News'
        });
      }
      
      return items;
    };

    const articles = parseXML(xmlData);
    console.log('Parsed articles count:', articles.length);

    if (articles.length > 0) {
      const latestArticle = articles[0];
      console.log('Returning latest article:', latestArticle.title);
      
      return res.status(200).json({
        success: true,
        article: latestArticle,
        timestamp: new Date().toISOString(),
        totalArticles: articles.length
      });
    } else {
      throw new Error('No articles found in RSS feed');
    }

  } catch (error) {
    console.error('Error in hacker-news API:', error);
    
    return res.status(200).json({
      success: false,
      error: error.message,
      article: {
        title: "Latest Cybersecurity News",
        description: "Unable to fetch latest news. Stay updated with   the latest cybersecurity threats and vulnerabilities by visiting The Hacker News directly.",
        image: "https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEgVlzRvr9tBHSRQqe_2jj8SrExmcCFhoLUrrMI4GzbM0-GggNMW0BTO02GXh8i_ShmsUpEJyy85FIPBXIbXwMjR68D30ldhn8osa8zG-wKqJu6KDR3Kuri6sd9GXMbhyannAnOJEQMY4tsxJ26pXPujtzzC-8U-kncd-YNj6LfRgiETNHccmSwQQY0zh3gQ/s1600/chrome.png",
        link: "https://thehackernews.com/",
        publishedAt: new Date().toISOString(),
        source: 'The Hacker News (Fallback)'
      }
    });
  }
}