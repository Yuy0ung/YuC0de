<template>
  <div>
    <h2>Rules</h2>
    <a-table :dataSource="rules" :columns="columns" rowKey="id" />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import axios from 'axios';

const rules = ref([]);
const columns = [
  { title: 'ID', dataIndex: 'id', key: 'id' },
  { title: 'Name', dataIndex: 'name', key: 'name' },
  { title: 'Severity', dataIndex: 'severity', key: 'severity' },
  { title: 'Language', dataIndex: 'language', key: 'language' },
  { title: 'Description', dataIndex: 'description', key: 'description' },
];

const fetchRules = async () => {
  const res = await axios.get('http://localhost:8080/api/rules');
  rules.value = res.data;
};

onMounted(fetchRules);
</script>
