<template>
  <div>
    <div style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <a-button type="primary" @click="showModal">New Scan</a-button>
        <a-button 
          type="primary" 
          danger 
          style="margin-left: 8px" 
          :disabled="!hasSelected" 
          @click="handleDelete"
        >
          Delete Selected
        </a-button>
        <span style="margin-left: 8px" v-if="hasSelected">
          {{ selectedRowKeys.length }} items selected
        </span>
      </div>
      <a-button @click="openAIConfig">AI Settings</a-button>
    </div>
    <a-table 
      :dataSource="tasks" 
      :columns="columns" 
      rowKey="id" 
      :loading="loading"
      :row-selection="{ selectedRowKeys: selectedRowKeys, onChange: onSelectChange }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'action'">
          <a-space>
            <router-link :to="'/task/' + record.id">
              <a-button type="link" size="small">Detail</a-button>
            </router-link>
            <router-link :to="'/cpg/' + record.id">
              <a-button type="link" size="small">CPG Analysis</a-button>
            </router-link>
          </a-space>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
        </template>
        <template v-else-if="column.key === 'created_at'">
          {{ formatDate(record.created_at) }}
        </template>
      </template>
    </a-table>

    <a-modal v-model:open="visible" title="New Scan Task" @ok="handleOk">
      <a-form layout="vertical">
        <a-form-item label="Source Type">
          <a-radio-group v-model:value="sourceType">
            <a-radio value="local">Local Directory</a-radio>
            <a-radio value="git">Git Repository</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item :label="sourceType === 'local' ? 'Target Path (Absolute Path)' : 'Git Repository URL'">
          <a-input v-model:value="targetPath" :placeholder="sourceType === 'local' ? '/Users/username/project' : 'https://github.com/username/repo.git'" />
        </a-form-item>
        <a-form-item label="AI Audit">
          <a-checkbox v-model:checked="aiEnabled">Enable AI Audit</a-checkbox>
        </a-form-item>
      </a-form>
    </a-modal>

    <a-modal v-model:open="aiConfigVisible" title="AI Configuration" @ok="saveAIConfig">
      <a-form layout="vertical">
        <a-form-item label="Base URL">
          <a-input v-model:value="aiConfig.base_url" placeholder="https://api.openai.com/v1" />
        </a-form-item>
        <a-form-item label="API Key">
          <a-input-password v-model:value="aiConfig.api_key" placeholder="sk-..." />
        </a-form-item>
        <a-form-item label="Model">
          <a-input v-model:value="aiConfig.model" placeholder="gpt-4" />
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, computed } from 'vue';
import axios from 'axios';
import { message, Modal } from 'ant-design-vue';

const tasks = ref([]);
const visible = ref(false);
const targetPath = ref('');
const sourceType = ref('local');
const loading = ref(false);
const selectedRowKeys = ref([]);
let eventSource = null;
let reconnectTimer = null;
const retryCount = ref(0);
const maxRetries = 15;

const aiEnabled = ref(false);
const aiConfigVisible = ref(false);
const aiConfig = ref({
  base_url: '',
  api_key: '',
  model: '',
  language: 'zh'
});

const openAIConfig = async () => {
  try {
    const res = await axios.get('http://localhost:8080/api/ai/config');
    aiConfig.value = res.data;
    aiConfigVisible.value = true;
  } catch (error) {
    // If config doesn't exist, just open empty form or default
    aiConfigVisible.value = true;
  }
};

const saveAIConfig = async () => {
  try {
    await axios.post('http://localhost:8080/api/ai/config', aiConfig.value);
    message.success('AI Config saved');
    aiConfigVisible.value = false;
  } catch (error) {
    message.error('Failed to save AI config');
  }
};

const hasSelected = computed(() => selectedRowKeys.value.length > 0);

const onSelectChange = (keys) => {
  selectedRowKeys.value = keys;
};

const columns = [
  { title: 'ID', dataIndex: 'id', key: 'id' },
  { title: 'Target', dataIndex: 'target', key: 'target' },
  { title: 'Source', dataIndex: 'source_type', key: 'source_type' },
  { title: 'Status', dataIndex: 'status', key: 'status' },
  { title: 'Vulnerabilities', dataIndex: 'vuln_count', key: 'vuln_count' },
  { title: 'Created At', dataIndex: 'created_at', key: 'created_at' },
  { title: 'Action', key: 'action' },
];

const fetchTasks = async () => {
  loading.value = true;
  try {
    const res = await axios.get('http://localhost:8080/api/tasks');
    tasks.value = res.data;
  } catch (error) {
    message.error('Failed to fetch tasks');
  } finally {
    loading.value = false;
  }
};

const showModal = () => {
  visible.value = true;
  targetPath.value = '';
  sourceType.value = 'local';
  aiEnabled.value = false;
};

const handleOk = async () => {
  if (!targetPath.value) {
    message.error('Please input target path/url');
    return;
  }
  try {
    await axios.post('http://localhost:8080/api/scan', { 
      target: targetPath.value,
      source_type: sourceType.value,
      ai_enabled: aiEnabled.value
    });
    message.success('Scan started');
    visible.value = false;
    // fetchTasks(); // SSE will update the list
  } catch (error) {
    message.error('Failed to start scan: ' + (error.response?.data?.error || error.message));
  }
};

const handleDelete = () => {
  Modal.confirm({
    title: 'Are you sure delete these tasks?',
    content: 'This will delete the tasks and associated data. For Git tasks, the cloned files will be removed.',
    okText: 'Yes',
    okType: 'danger',
    cancelText: 'No',
    async onOk() {
      try {
        await axios.post('http://localhost:8080/api/tasks/delete', { ids: selectedRowKeys.value });
        message.success('Tasks deleted');
        selectedRowKeys.value = [];
        // fetchTasks(); // SSE will update the list
      } catch (error) {
        message.error('Failed to delete tasks: ' + (error.response?.data?.error || error.message));
      }
    },
  });
};

const statusColor = (status) => {
  if (status === 'COMPLETED') return 'green';
  if (status === 'RUNNING') return 'blue';
  if (status === 'FAILED') return 'red';
  return 'orange';
};

const formatDate = (dateString) => {
  if (!dateString) return '';
  const date = new Date(dateString);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}年${month}月${day}日 ${hours}:${minutes}:${seconds}`;
};

const setupSSE = () => {
  if (eventSource) {
    eventSource.close();
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }

  eventSource = new EventSource('http://localhost:8080/api/tasks/stream');
  
  eventSource.onopen = () => {
    console.log('SSE connected');
    retryCount.value = 0;
  };

  eventSource.onmessage = (event) => {
    try {
      tasks.value = JSON.parse(event.data);
    } catch (e) {
      console.error('Failed to parse SSE data', e);
    }
  };

  eventSource.onerror = (error) => {
    console.error('SSE error', error);
    eventSource.close();
    
    if (retryCount.value < maxRetries) {
      retryCount.value++;
      console.log(`SSE Reconnecting... attempt ${retryCount.value}/${maxRetries}`);
      reconnectTimer = setTimeout(() => {
        setupSSE();
      }, 5000);
    } else {
      message.error('连接已断开，请手动刷新页面重试');
    }
  };
};

onMounted(() => {
  // Initial fetch is handled by SSE connection or we can keep one explicit fetch
  fetchTasks(); 
  setupSSE();
});

onUnmounted(() => {
  if (eventSource) {
    eventSource.close();
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
  }
});
</script>
