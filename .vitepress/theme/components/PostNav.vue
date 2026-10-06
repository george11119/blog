<template>
  <nav class="post-nav" v-if="index !== -1 && (prev || next)">
    <a v-if="prev" class="post-nav-link prev" :href="withBase(prev.regularPath)">
      <span class="post-nav-desc">← Previous post</span>
      <span class="post-nav-title">{{ prev.frontMatter.title }}</span>
    </a>
    <span v-else></span>
    <a v-if="next" class="post-nav-link next" :href="withBase(next.regularPath)">
      <span class="post-nav-desc">Next post →</span>
      <span class="post-nav-title">{{ next.frontMatter.title }}</span>
    </a>
  </nav>
</template>
<script lang="ts" setup>
import { computed } from 'vue'
import { useData, withBase } from 'vitepress'

const { page, theme } = useData()

// theme.posts is sorted newest first, so the older post sits at index + 1
const posts = computed(() => theme.value.posts)
const index = computed(() =>
  posts.value.findIndex((post: any) => post.regularPath === '/' + page.value.relativePath.replace(/\.md$/, '.html'))
)
const prev = computed(() => (index.value === -1 ? null : posts.value[index.value + 1]))
const next = computed(() => (index.value > 0 ? posts.value[index.value - 1] : null))
</script>

<style>
.post-nav {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-top: 48px;
  padding-top: 24px;
  border-top: 1px solid var(--vp-c-divider);
}
.post-nav-link {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 12px 16px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  transition: border-color 0.25s;
}
.post-nav-link:hover {
  border-color: var(--vp-c-brand);
}
.post-nav-link.next {
  text-align: right;
}
.post-nav-desc {
  font-size: 12px;
  color: var(--vp-c-text-2);
}
.post-nav-title {
  font-size: 14px;
  font-weight: 500;
  color: var(--vp-c-brand);
}
@media (max-width: 640px) {
  .post-nav {
    grid-template-columns: 1fr;
  }
  .post-nav > span:empty {
    display: none;
  }
}
</style>
