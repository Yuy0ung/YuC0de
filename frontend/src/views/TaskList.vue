<template>
  <div>
    <div style="margin-bottom: 16px">
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
    <a-table 
      :dataSource="tasks" 
      :columns="columns" 
      rowKey="id" 
      :loading="loading"
      :row-selection="{ selectedRowKeys: selectedRowKeys, onChange: onSelectChange }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'action'">
          <router-link :to="'/task/' + record.id">View Details</router-link>
        </template>
        <template v-else-if="column.key === 'status'">
          <a-tag :color="statusColor(record.status)">{{ record.status }}</a-tag>
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
      </a-form>
    </a-modal>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import axios from 'axios';
import { message, Modal } from 'ant-design-vue';

const tasks = ref([]);
const visible = ref(false);
const targetPath = ref('');
const sourceType = ref('local');
const loading = ref(false);
const selectedRowKeys = ref([]);

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
};

const handleOk = async () => {
  if (!targetPath.value) {
    message.error('Please input target path/url');
    return;
  }
  try {
    await axios.post('http://localhost:8080/api/scan', { 
      target: targetPath.value,
      source_type: sourceType.value
    });
    message.success('Scan started');
    visible.value = false;
    fetchTasks();
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
        fetchTasks();
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

onMounted(() => {
  fetchTasks();
  // Poll every 5 seconds (silent update without loading spinner)
  setInterval(async () => {
    try {
      const res = await axios.get('http://localhost:8080/api/tasks');
      tasks.value = res.data;
    } catch (e) {
      // ignore
    }
  }, 5000);
});
</script>
