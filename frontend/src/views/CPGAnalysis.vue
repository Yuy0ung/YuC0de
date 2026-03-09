<template>
  <div style="display: flex; height: calc(100vh - 200px);">
    <!-- Sidebar -->
    <div style="width: 300px; border-right: 1px solid #eee; display: flex; flex-direction: column; background: #fff;">
      <div style="padding: 16px; border-bottom: 1px solid #eee;">
        <h3 style="margin-bottom: 16px;">CPG Analysis</h3>
        <a-input-search
          v-model:value="searchText"
          placeholder="Search class/method..."
          style="width: 100%"
          @search="onSearch"
        />
      </div>
      <div style="flex: 1; overflow-y: auto;">
        <a-spin :spinning="loadingNodes">
          <a-list item-layout="horizontal" :data-source="filteredNodes">
            <template #renderItem="{ item }">
              <a-list-item 
                @click="selectNode(item)" 
                style="cursor: pointer; padding: 10px 16px;"
                :class="{ 'selected-node': selectedNodeId === item.id }"
              >
                <a-list-item-meta>
                  <template #title>
                    <a-tooltip :title="item.label" placement="topLeft">
                      <span :style="{ color: getNodeColor(item.type) }">
                        <component :is="getNodeIcon(item.type)" /> {{ item.label }}
                      </span>
                    </a-tooltip>
                  </template>
                  <template #description>
                    <span style="font-size: 12px; color: #999;">{{ item.type }}</span>
                  </template>
                </a-list-item-meta>
              </a-list-item>
            </template>
          </a-list>
        </a-spin>
      </div>
    </div>

    <!-- Main Graph Area -->
    <div style="flex: 1; position: relative; background: #fafafa;">
      <div id="cpg-container" style="width: 100%; height: 100%;"></div>
      <div v-if="!selectedNodeId" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: #999;">
        Select a node to view CPG
      </div>
      <a-spin v-if="loadingGraph" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);" />
      
      <!-- Legend -->
      <div style="position: absolute; bottom: 20px; right: 20px; background: rgba(255,255,255,0.8); padding: 10px; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.15);">
        <div v-for="(color, type) in nodeColors" :key="type" style="display: flex; align-items: center; margin-bottom: 4px;">
          <span :style="{ background: color, width: '12px', height: '12px', borderRadius: '50%', marginRight: '8px' }"></span>
          <span style="font-size: 12px;">{{ type }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import axios from 'axios';
import { message } from 'ant-design-vue';
import { Network } from 'vis-network';
import { DataSet } from 'vis-data';
import 'vis-network/styles/vis-network.css';
import { 
  FileOutlined, 
  FunctionOutlined, 
  FieldStringOutlined,
  CodeOutlined
} from '@ant-design/icons-vue';

const route = useRoute();
const taskId = route.params.id;

const nodes = ref([]);
const searchText = ref('');
const loadingNodes = ref(false);
const loadingGraph = ref(false);
const selectedNodeId = ref(null);
const network = ref(null);

const nodeColors = {
  class: '#1890ff',
  method: '#52c41a',
  field: '#faad14',
  variable: '#722ed1',
  expression: '#8c8c8c',
  control: '#f5222d',
  return: '#eb2f96'
};

const getNodeColor = (type) => nodeColors[type] || '#8c8c8c';

const getNodeIcon = (type) => {
  switch(type) {
    case 'class': return FileOutlined;
    case 'method': return FunctionOutlined;
    case 'field': return FieldStringOutlined;
    default: return CodeOutlined;
  }
};

const getEdgeColor = (type) => {
  switch(type) {
    case 'HAS_METHOD': return '#8c8c8c';
    case 'HAS_FIELD': return '#8c8c8c';
    case 'CALLS': return '#52c41a'; // Green
    case 'ACCESS': return '#faad14'; // Orange
    case 'EXTENDS': return '#1890ff'; // Blue
    case 'AST': return '#bfbfbf'; // Light Gray
    case 'CFG': return '#f5222d'; // Red
    case 'PDG': return '#722ed1'; // Purple
    case 'RECURSION': return '#eb2f96'; // Magenta
    default: return '#ccc';
  }
};

const filteredNodes = computed(() => {
  if (!searchText.value) return nodes.value;
  return nodes.value.filter(n => 
    n.label.toLowerCase().includes(searchText.value.toLowerCase())
  );
});

const fetchNodes = async () => {
  loadingNodes.value = true;
  try {
    const res = await axios.get(`http://localhost:8080/api/cpg/nodes/${taskId}`);
    nodes.value = res.data;
  } catch (error) {
    message.error('Failed to fetch nodes');
  } finally {
    loadingNodes.value = false;
  }
};

const selectNode = async (node) => {
  selectedNodeId.value = node.id;
  loadingGraph.value = true;
  
  try {
    const res = await axios.get(`http://localhost:8080/api/cpg/graph/${taskId}`, {
      params: { node: node.id }
    });
    renderGraph(res.data);
  } catch (error) {
    message.error('Failed to fetch CPG graph');
  } finally {
    loadingGraph.value = false;
  }
};

const renderGraph = (data) => {
  if (network.value) {
    network.value.destroy();
    network.value = null;
  }

  const container = document.getElementById('cpg-container');
  
  // Transform data for vis-network
  const visNodes = new DataSet(data.nodes.map(n => ({
    id: n.id,
    label: n.label.length > 20 ? n.label.substring(0, 18) + '...' : n.label,
    title: `Type: ${n.type}\nLabel: ${n.label}`, // Tooltip
    color: {
      background: getNodeColor(n.type) + '20',
      border: getNodeColor(n.type),
      highlight: {
        background: getNodeColor(n.type) + '40',
        border: getNodeColor(n.type),
      }
    },
    shape: 'dot',
    size: 20,
    font: { size: 12, color: '#333' },
    borderWidth: 2,
    shadow: true,
  })));

  const visEdges = new DataSet(data.edges.map(e => ({
    from: e.source,
    to: e.target,
    label: e.type,
    title: e.label || e.type,
    color: {
      color: getEdgeColor(e.type),
      highlight: '#1890ff',
    },
    arrows: e.type === 'EXTENDS' ? { to: { enabled: true, type: 'arrow' } } : 'to',
    dashes: e.type === 'PDG' || e.type === 'ACCESS',
    smooth: {
      type: 'cubicBezier',
      forceDirection: 'horizontal',
      roundness: 0.4
    },
    font: { align: 'top', size: 10, color: '#666', background: 'rgba(255,255,255,0.7)' },
  })));

  const options = {
    nodes: {
      shape: 'dot',
      size: 16,
    },
    edges: {
      length: 300, // Explicitly increase edge length
    },
    physics: {
      forceAtlas2Based: {
        gravitationalConstant: -50,
        centralGravity: 0.01,
        springLength: 300, // Increase spring length for longer edges
        springConstant: 0.08,
      },
      maxVelocity: 50,
      solver: 'forceAtlas2Based',
      timestep: 0.35,
      stabilization: { iterations: 150 },
    },
    interaction: {
      hover: true,
      tooltipDelay: 200,
      zoomView: true,
      dragView: true,
    },
    layout: {
      improvedLayout: true,
    }
  };

  network.value = new Network(container, { nodes: visNodes, edges: visEdges }, options);
  
  network.value.on("click", function (params) {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const node = visNodes.get(nodeId);
      console.log('Clicked node:', node);
    }
  });
};

const onSearch = () => {
  // filteredNodes computed property handles this
};

onMounted(() => {
  fetchNodes();
});

onUnmounted(() => {
  if (network.value) {
    network.value.destroy();
  }
});
</script>

<style scoped>
.selected-node {
  background-color: #e6f7ff;
}
</style>
