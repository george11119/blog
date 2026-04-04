import path from 'path'
import { writeFileSync } from 'fs'
import { Feed } from 'feed'
import { defineConfig, createContentLoader, type SiteConfig } from 'vitepress'
import { getPosts } from './theme/serverUtils'

//每页的文章数量
const pageSize = 10

const isProd = process.env.NODE_ENV === 'production'
const hostname: string = 'https://www.georgemao.com'

export default defineConfig({
  title: "George's blog",
  base: '/',
  cacheDir: './node_modules/vitepress_cache',
  description: 'A place to host my CTF writeups and security research',
  ignoreDeadLinks: false,
  themeConfig: {
    posts: await getPosts(pageSize),
    website: 'https://github.com/george11119', //copyright link
    comment: {
      repo: '',
      repoId: '',
      categoryId: ''
    },
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Archives', link: '/pages/archives' },
      // { text: 'Categories', link: '/pages/category' },
      // { text: 'Tags', link: '/pages/tags' },
      { text: 'About', link: '/pages/about' }
      // { text: 'Airene', link: 'http://airene.net' }  -- External link test
    ],
    // search: {
    //   provider: 'local'
    // },
    //outline:[2,3],
    // outline: {
    //   label: '文章摘要'
    // },
    socialLinks: [
      { icon: 'rss', link: '/feed.xml' },
      { icon: 'github', link: 'https://github.com/george11119' }
    ]
  } as any,

  srcExclude: isProd
    ? [
        '**/trash/**/*.md', // 排除所有 trash 目录
        '**/draft/**/*.md', // 递归排除子目录
        '**/private-notes/*.md', // 排除特定文件
        'README.md'
      ]
    : ['README.md'],
  vite: {
    //build: { minify: false }
    server: { port: 5000 }
  },
  markdown: {
    emoji: {
      enabled: ['false']
    }
  },
  sitemap: {
    hostname: hostname
  },
  // rewrites(id) {
  //   return id.replace(/\d\d\d\d-\d\d-\d\d-(.*)\/index/, '$1')
  // }
  buildEnd: async (config: SiteConfig) => {
    const feed = new Feed({
      title: "George's blog",
      description: 'My personal blog',
      id: hostname,
      link: hostname,
      language: 'en',
      image: '',
      favicon: `${hostname}/favicon.ico`,
      copyright: ''
    })

    // You might need to adjust this if your Markdown files
    // are located in a subfolder
    const posts = await createContentLoader('posts/**/*.md', {
      excerpt: true,
      render: true
    }).load()

    posts.sort((a, b) => +new Date(b.frontmatter.date as string) - +new Date(a.frontmatter.date as string))

    for (const { url, excerpt, frontmatter, html } of posts) {
      feed.addItem({
        title: frontmatter.title,
        id: `${hostname}${url}`,
        link: `${hostname}${url}`,
        description: excerpt,
        content: html,
        author: [
          {
            name: 'George Mao',
            email: '',
            link: hostname + '/pages/about.html'
          }
        ],
        date: new Date(frontmatter.date)
      })
    }

    writeFileSync(path.join(config.outDir, 'feed.xml'), feed.atom1())
  }
})
