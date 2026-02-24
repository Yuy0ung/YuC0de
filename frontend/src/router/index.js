import { createRouter, createWebHistory } from 'vue-router'
import TaskList from '../views/TaskList.vue'
import TaskDetail from '../views/TaskDetail.vue'
import RuleEditor from '../views/RuleEditor.vue'

const routes = [
  { path: '/', component: TaskList },
  { path: '/task/:id', component: TaskDetail },
  { path: '/rules', component: RuleEditor },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
