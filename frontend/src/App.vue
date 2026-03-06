<template>
  <a-layout style="min-height: 100vh">
    <a-layout-header style="padding: 0 12px;">
      <div class="logo" style="float: left; margin-right: 20px; display: flex; align-items: center; height: 64px;">
        <img src="/yuc0de.svg" alt="YuC0de Logo" style="height: 40px; border-radius: 6px; margin-right: 12px;" />
        <span style="color: white; font-size: 20px; font-weight: bold; letter-spacing: 1px;">YuC0de</span>
      </div>
      <a-menu theme="dark" mode="horizontal" :style="{ lineHeight: '64px' }">
        <a-menu-item key="1">
          <router-link to="/">Tasks</router-link>
        </a-menu-item>
        <a-menu-item key="2">
          <router-link to="/rules">Rules</router-link>
        </a-menu-item>
      </a-menu>
    </a-layout-header>
    <a-layout-content style="padding: 0 50px; margin-top: 20px;">
      <div :style="{ background: '#fff', padding: '24px', minHeight: '280px' }">
        <router-view></router-view>
      </div>
    </a-layout-content>
    <a-layout-footer style="text-align: center">
      YuC0de ©2026 Created by Yuy0ung  
    </a-layout-footer>
  </a-layout>
</template>

<script setup>
</script>

<style>
body {
  margin: 0;
}
</style>
