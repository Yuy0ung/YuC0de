<template>
  <div>
    <div style="margin-bottom: 16px;">
      <a-button type="primary" @click="showCreateModal">新建规则</a-button>
      <a-button type="primary" danger :disabled="!hasSelected" @click="handleDelete" style="margin-left: 8px">删除规则</a-button>
    </div>
    <a-table 
      :dataSource="rules" 
      :columns="columns" 
      rowKey="filename" 
      :rowClassName="(record) => record.enabled === false ? 'disabled-row' : ''" 
      :loading="loading"
      :row-selection="{ selectedRowKeys: selectedRowKeys, onChange: onSelectChange }"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'status'">
          <a-switch :checked="record.enabled !== false" @change="(checked) => handleToggle(record, checked)" />
        </template>
        <template v-if="column.key === 'action'">
          <a-button type="primary" @click="handleEdit(record)">编辑</a-button>
        </template>
      </template>
    </a-table>

    <a-modal v-model:open="isModalVisible" :title="modalTitle" width="800px" @ok="handleSave">
      <div v-if="isCreating" style="margin-bottom: 16px;">
        <a-input v-model:value="newFilename" placeholder="请输入规则文件名 (例如: my-rule.yaml)" addon-after=".yaml" />
      </div>
      <div style="height: 500px; border: 1px solid #d9d9d9; border-radius: 4px; overflow: hidden;">
        <codemirror
          v-model="currentRuleContent"
          placeholder="请输入规则内容..."
          :style="{ height: '100%' }"
          :autofocus="true"
          :tab-size="2"
          :extensions="extensions"
        />
      </div>
    </a-modal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';
import { message, Modal } from 'ant-design-vue';
import { Codemirror } from 'vue-codemirror';
import { yaml } from '@codemirror/lang-yaml';
import { oneDark } from '@codemirror/theme-one-dark';

const rules = ref([]);
const loading = ref(false);
const isModalVisible = ref(false);
const isCreating = ref(false);
const newFilename = ref('');
const currentRule = ref(null);
const currentRuleContent = ref('');
const selectedRowKeys = ref([]);

const hasSelected = computed(() => selectedRowKeys.value.length > 0);
const modalTitle = computed(() => isCreating.value ? '新建规则' : '编辑规则');

const extensions = [yaml(), oneDark];

const columns = [
  { title: 'ID', dataIndex: 'id', key: 'id' },
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '等级', dataIndex: 'severity', key: 'severity' },
  { title: '描述', dataIndex: 'description', key: 'description' },
  { title: '状态', key: 'status' },
  { title: '操作', key: 'action' },
];

const fetchRules = async () => {
  loading.value = true;
  try {
    const res = await axios.get('http://localhost:8080/api/rules');
    rules.value = res.data;
  } catch (error) {
    message.error('获取规则列表失败');
  } finally {
    loading.value = false;
  }
};

const onSelectChange = (keys) => {
  selectedRowKeys.value = keys;
};

const handleToggle = async (record, checked) => {
  try {
    await axios.post('http://localhost:8080/api/rules/toggle', {
      filename: record.filename,
      enabled: checked
    });
    // Update local state directly to reflect change immediately
    const rule = rules.value.find(r => r.id === record.id);
    if (rule) {
      rule.enabled = checked;
    }
    message.success(`规则已${checked ? '启用' : '禁用'}`);
  } catch (error) {
    message.error('操作失败');
    // Revert switch state on error (optional, but good UX)
    fetchRules();
  }
};

const showCreateModal = () => {
  isCreating.value = true;
  newFilename.value = '';
  currentRuleContent.value = `id: new-rule
name: 新规则
severity: LOW
description: 新规则描述
patterns:
  - "pattern"`;
  isModalVisible.value = true;
};

const handleEdit = (record) => {
  isCreating.value = false;
  currentRule.value = record;
  currentRuleContent.value = record.content;
  isModalVisible.value = true;
};

const handleDelete = () => {
  Modal.confirm({
    title: '确认删除',
    content: `确定要删除选中的 ${selectedRowKeys.value.length} 条规则吗？`,
    okText: '确认',
    cancelText: '取消',
    onOk: async () => {
      try {
        await axios.post('http://localhost:8080/api/rules/delete', {
          filenames: selectedRowKeys.value
        });
        message.success('规则删除成功');
        selectedRowKeys.value = [];
        fetchRules();
      } catch (error) {
        message.error('删除失败');
      }
    }
  });
};

const handleSave = async () => {
  try {
    if (isCreating.value) {
      if (!newFilename.value) {
        message.error('请输入文件名');
        return;
      }
      await axios.post('http://localhost:8080/api/rules/create', {
        filename: newFilename.value,
        content: currentRuleContent.value
      });
      message.success('规则创建成功');
    } else {
      await axios.post('http://localhost:8080/api/rules/update', {
        filename: currentRule.value.filename,
        content: currentRuleContent.value
      });
      message.success('规则已更新');
    }
    isModalVisible.value = false;
    fetchRules();
  } catch (error) {
    message.error(isCreating.value ? '规则创建失败' : '规则更新失败');
    console.error(error);
  }
};

onMounted(fetchRules);
</script>

<style scoped>
.disabled-row {
  opacity: 0.5;
  background-color: #f5f5f5;
}
</style>
