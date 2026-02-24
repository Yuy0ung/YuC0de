<template>
  <div style="display: flex; height: 80vh; overflow: hidden;">
    <div style="flex: 0 0 300px; display: flex; flex-direction: column; border-right: 1px solid #f0f0f0; background: #fff;">
      <div style="padding: 16px; border-bottom: 1px solid #f0f0f0;">
        <h3 style="margin: 0;">Vulnerabilities</h3>
      </div>
      <div style="flex: 1; overflow-y: auto;">
        <a-spin :spinning="loading">
          <a-list item-layout="horizontal" :data-source="vulns">
            <template #renderItem="{ item }">
              <a-list-item @click="selectVuln(item)" style="cursor: pointer; padding: 12px 16px;" :class="{ 'selected-item': selectedVuln && selectedVuln.id === item.id }">
                <a-list-item-meta>
                  <template #title>
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                      <span style="font-weight: 500;">{{ item.rule_name }}</span>
                      <a-tag :color="item.severity === 'HIGH' ? 'red' : 'orange'" style="margin-right: 0;">{{ item.severity }}</a-tag>
                    </div>
                  </template>
                  <template #description>
                    <div style="font-size: 12px; color: #888; margin-top: 4px; word-break: break-all;">
                      {{ item.file_path }}:{{ item.line_number }}
                    </div>
                  </template>
                </a-list-item-meta>
              </a-list-item>
            </template>
          </a-list>
        </a-spin>
      </div>
    </div>
    
    <div style="flex: 1; display: flex; flex-direction: column; overflow: hidden; background: #fff;">
      <div v-if="selectedVuln" style="flex: 1; display: flex; flex-direction: column; overflow: hidden;">
        <div style="padding: 16px; border-bottom: 1px solid #f0f0f0;">
          <h3 style="margin: 0 0 8px 0;">Code Preview</h3>
          <div style="margin-bottom: 8px;">
             <a-tag color="blue">Line {{ currentActiveLine }}</a-tag>
             <span style="color: #666;">{{ getRelativePath(currentFilePath) }}</span>
          </div>
        </div>
        
        <div class="code-preview-container" ref="codeContainer">
          <a-spin :spinning="codeLoading">
             <div class="code-wrapper" v-if="!codeLoading && fileContent">
                <div class="line-numbers">
                   <div v-for="n in totalLines" :key="n" class="line-num" :class="{ 'active-num': n === currentActiveLine }">{{ n }}</div>
                </div>
                <div class="code-body">
                   <div class="indent-layer">
                      <div v-for="(guides, lineIdx) in indentations" :key="lineIdx" class="indent-line" :style="{ top: (lineIdx * 20) + 'px' }">
                        <span v-for="offset in guides" :key="offset" class="indent-guide" :style="{ left: offset + 'ch' }"></span>
                      </div>
                   </div>
                   <div class="line-highlight" v-if="currentActiveLine > 0" :style="{ top: ((currentActiveLine - 1) * 20) + 'px' }"></div>
                   <pre><code class="hljs" v-html="highlightedCode"></code></pre>
                </div>
             </div>
          </a-spin>
        </div>

        <!-- Taint Flow Steps -->
        <div style="height: 250px; overflow-y: auto; border-top: 1px solid #f0f0f0; padding: 16px; background: #fff;">
          <div style="font-weight: 500; margin-bottom: 12px; font-size: 14px;">Taint Flow Trace</div>
          
          <div v-if="selectedVuln.steps && selectedVuln.steps.length > 0">
            <div style="display: flex; flex-direction: column; gap: 8px;">
              <div 
                v-for="(step, index) in selectedVuln.steps" 
                :key="index" 
                class="step-item" 
                :class="{ 'active-step': step.line_number === currentActiveLine && step.file_path === currentFilePath }"
                @click="handleStepClick(step)"
              >
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span style="font-weight: bold; font-size: 13px;">{{ index + 1 }}. {{ step.description }}</span>
                    <a-tag color="blue" style="margin: 0;">Line {{ step.line_number }}</a-tag>
                </div>
                <div style="font-size: 12px; color: #666; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    {{ step.line_content }}
                </div>
              </div>
            </div>
          </div>
          <div v-else-if="selectedVuln.steps_json && selectedVuln.steps_json !== 'null'" style="padding: 8px; background: #f0f0f0; border-radius: 4px;">
             <div style="color: #666; font-size: 12px;">Trace steps available in JSON format but not parsed correctly.</div>
          </div>
          <div v-else-if="selectedVuln.rule_name && selectedVuln.rule_name.includes('Data Flow')" style="color: #cf1322; font-size: 13px;">
            No taint path found or displayed.
          </div>
        </div>
      </div>
      <div v-else style="flex: 1; display: flex; justify-content: center; align-items: center; color: #999;">
        <a-empty description="Select a vulnerability to view details" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, nextTick } from 'vue';
import { useRoute } from 'vue-router';
import axios from 'axios';
import { message } from 'ant-design-vue';
import hljs from 'highlight.js/lib/core';
import java from 'highlight.js/lib/languages/java';
import xml from 'highlight.js/lib/languages/xml';
import javascript from 'highlight.js/lib/languages/javascript';
import 'highlight.js/styles/github.css';

hljs.registerLanguage('java', java);
hljs.registerLanguage('xml', xml);
hljs.registerLanguage('javascript', javascript);

const route = useRoute();
const vulns = ref([]);
const selectedVuln = ref(null);
const codeContainer = ref(null);
const highlightedCode = ref('');
const loading = ref(false);
const codeLoading = ref(false);
const fileContent = ref('');
const currentFilePath = ref('');
const currentActiveLine = ref(0);
const totalLines = ref(0);
const indentations = ref([]);
const taskTarget = ref('');

const fetchTask = async () => {
  loading.value = true;
  selectedVuln.value = null; // Reset selection on refresh
  try {
    const res = await axios.get(`http://localhost:8080/api/tasks/${route.params.id}`);
    if (res.data.task && res.data.task.target) {
      taskTarget.value = res.data.task.target;
    }
    // Pre-process vulnerabilities to parse steps_json
    vulns.value = res.data.vulns.map(v => {
      let steps = [];
      if (v.steps && v.steps.length > 0) {
        steps = v.steps;
      } else if (v.steps_json && v.steps_json !== "null") {
        try {
          const parsed = JSON.parse(v.steps_json);
          steps = Array.isArray(parsed) ? parsed : [];
        } catch (e) {
          console.error('Failed to parse steps_json for vuln', v.id, e);
        }
      }
      return {
        ...v,
        steps: steps
      };
    });
  } catch (error) {
    message.error('Failed to fetch task details');
  } finally {
    loading.value = false;
  }
};

watch(() => route.params.id, (newId) => {
  if (newId) {
    fetchTask();
  }
});

const selectVuln = async (vuln) => {
  selectedVuln.value = vuln;
  codeLoading.value = true;
  currentFilePath.value = vuln.file_path;
  currentActiveLine.value = vuln.line_number;
  try {
    const res = await axios.get(`http://localhost:8080/api/files?path=${vuln.file_path}&task_id=${route.params.id}`);
    fileContent.value = res.data.content;
    renderCode(res.data.content, vuln.line_number, vuln.file_path);
  } catch (error) {
    message.error('Failed to load file content');
  } finally {
    codeLoading.value = false;
  }
};

const handleStepClick = async (step) => {
  currentActiveLine.value = step.line_number;
  if (step.file_path !== currentFilePath.value) {
    codeLoading.value = true;
    try {
      const res = await axios.get(`http://localhost:8080/api/files?path=${step.file_path}&task_id=${route.params.id}`);
      fileContent.value = res.data.content;
      currentFilePath.value = step.file_path;
      renderCode(res.data.content, step.line_number, step.file_path);
    } catch (error) {
       message.error('Failed to load file content');
    } finally {
       codeLoading.value = false;
    }
  } else {
     // Just scroll
     jumpToLine(step.line_number);
  }
};

const renderCode = (content, activeLine, filePath) => {
  totalLines.value = content.split('\n').length;
  
  // Calculate indentations
  const lines = content.split('\n');
  indentations.value = lines.map(line => {
      // Replace tabs with 4 spaces for calculation if needed, but here assuming spaces
      // Just count leading spaces
      const match = line.match(/^ +/);
      const spaceCount = match ? match[0].length : 0;
      const guides = [];
      // Draw guide every 4 spaces, but not at the very end cursor position?
      // VS Code style: guides are at 0, 4, 8...
      for (let i = 0; i < spaceCount; i += 4) {
          guides.push(i);
      }
      return guides;
  });

  // Detect language
  let language = 'java'; // default
  if (filePath.endsWith('.xml')) language = 'xml';
  if (filePath.endsWith('.js')) language = 'javascript';
  
  // Highlight
  try {
    const result = hljs.highlight(content, { language, ignoreIllegals: true });
    highlightedCode.value = result.value;
  } catch (e) {
    // Fallback
    highlightedCode.value = escapeHtml(content);
  }
  
  // Auto scroll to line
  nextTick(() => {
    jumpToLine(activeLine);
  });
};

const jumpToLine = (lineNum) => {
  if (codeContainer.value) {
    const lineHeight = 20; // Must match CSS
    const targetTop = (lineNum - 1) * lineHeight;
    const containerHeight = codeContainer.value.clientHeight;
    
    // Scroll to center the line
    codeContainer.value.scrollTo({
      top: targetTop - (containerHeight / 2) + (lineHeight / 2),
      behavior: 'smooth'
    });
  }
};

const getRelativePath = (path) => {
  if (!path) return '';
  // If we have task target, try to remove it from path
  if (taskTarget.value && path.startsWith(taskTarget.value)) {
    let rel = path.substring(taskTarget.value.length);
    if (rel.startsWith('/')) rel = rel.substring(1);
    // If empty (root), return path or something
    if (rel === '') return path;
    return rel;
  }
  
  // Fallback: try to find common project roots like 'src/'
  const srcIndex = path.indexOf('/src/');
  if (srcIndex !== -1) {
    return path.substring(srcIndex + 1); // keep src/
  }
  
  return path;
};

const escapeHtml = (text) => {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

onMounted(fetchTask);
</script>

<style scoped>
.selected-item {
  background-color: #e6f7ff;
  border-right: 3px solid #1890ff;
}

.code-preview-container {
  flex: 1;
  overflow: auto; /* Handles vertical scroll for the whole code block */
  background: #fff;
  position: relative;
}

.code-wrapper {
  display: flex;
  min-width: 100%;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 20px; /* FIXED LINE HEIGHT */
  padding: 10px 0; /* Vertical breathing room for both columns */
}

.line-numbers {
  flex: 0 0 50px;
  background: #fafafa;
  border-right: 1px solid #eee;
  text-align: right;
  padding: 0; 
  user-select: none;
  color: #bbb;
}

.line-num {
  padding-right: 15px; /* Increase gap between number and border */
  height: 20px; /* Match line-height */
  box-sizing: border-box;
}

.active-num {
  color: #333;
  font-weight: bold;
}

.code-body {
  flex: 1;
  position: relative;
  overflow-x: auto; /* Horizontal scroll */
  padding: 0 0 0 15px; /* Left padding only, vertical comes from wrapper */
}

.code-body pre {
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  border: none;
  font-family: inherit;
  font-size: inherit;
  line-height: inherit;
}

.code-body code {
  white-space: pre; /* Disable wrapping */
  font-family: inherit;
  padding: 0 !important; /* CRITICAL: Remove highlight.js default padding */
  margin: 0 !important;
}

.line-highlight {
  position: absolute;
  left: 0;
  right: 0;
  height: 20px;
  background-color: #fff1b8; /* Highlight color */
  pointer-events: none;
  z-index: 0;
  width: 100%;
}

/* Ensure code is above highlight */
.code-body pre {
  position: relative;
  z-index: 2;
  background: transparent !important;
}

/* Force highlight.js background/padding to be transparent/zero */
:deep(.hljs) {
  background: transparent !important;
  padding: 0 !important; /* CRITICAL: Remove highlight.js default padding */
  margin: 0 !important;
}

.indent-layer {
  position: absolute;
  top: 0;
  left: 15px; /* Must match code-body padding-left */
  bottom: 0;
  right: 0;
  z-index: 1;
  pointer-events: none;
}

.indent-line {
  position: absolute;
  left: 0;
  right: 0;
  height: 20px;
}

.indent-guide {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 1px;
  background-color: #e8e8e8;
  /* Visual tweak to look like | */
}

.line-highlight {
  position: absolute;
  left: 0;
  right: 0;
  height: 20px;
  background-color: rgba(255, 241, 184, 0.6); /* Semi-transparent */
  pointer-events: none;
  z-index: 3; /* On top of code */
  width: 100%;
  mix-blend-mode: multiply;
}

/* Step List Styling */
.step-item {
  cursor: pointer;
  background: #f9f9f9;
  border: 1px solid #f0f0f0;
  border-radius: 6px;
  padding: 8px 12px;
  transition: all 0.3s;
  width: 100%; /* Full width */
  box-sizing: border-box;
}

/* Force ant-steps content to be full width */
:deep(.ant-steps-item-content) {
  width: 100% !important;
}
:deep(.ant-steps-item-title) {
  width: 100% !important;
  padding-right: 0 !important;
}

.step-item:hover {
  background: #e6f7ff;
  border-color: #91d5ff;
}

.active-step {
  background: #e6f7ff;
  border-color: #1890ff;
  box-shadow: 0 2px 4px rgba(0,0,0,0.05);
}

/* Scrollbar styling */
::-webkit-scrollbar {
  width: 8px;
  height: 8px;
}
::-webkit-scrollbar-thumb {
  background: #ccc;
  border-radius: 4px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
</style>
