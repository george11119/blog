import { defineConfig } from 'vitepress'
import { getPosts } from './theme/serverUtils'

//每页的文章数量
const pageSize = 10

const isProd = process.env.NODE_ENV === 'production'

export default defineConfig({
  title: 'Vitepress blog',
  base: '/',
  cacheDir: './node_modules/vitepress_cache',
  description: 'vitepress,blog,blog-theme',
  ignoreDeadLinks: true,
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
      { text: 'Categories', link: '/pages/category' },
      // { text: 'Tags', link: '/pages/tags' },
      { text: 'About', link: '/pages/about' }
      // { text: 'Airene', link: 'http://airene.net' }  -- External link test
    ],
    search: {
      provider: 'local'
    },
    //outline:[2,3],
    outline: {
      label: '文章摘要'
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/george11119' }]
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
  }

  /*
      optimizeDeps: {
          keepNames: true
      }
      */
})
