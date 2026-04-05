const aiModule = {
  conversationHistory: [],
  isStreaming: false,

  init() {
    const input = document.getElementById('ai-input');
    const sendBtn = document.getElementById('ai-send-btn');

    if (sendBtn) {
      sendBtn.addEventListener('click', () => this.sendFromInput());
    }

    if (input) {
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.sendFromInput();
        }
      });
    }
  },

  sendFromInput() {
    const input = document.getElementById('ai-input');
    const message = input?.value.trim();
    if (!message || this.isStreaming) return;

    input.value = '';
    this.sendMessage(message);
  },

  async sendMessage(message, scanId = null) {
    if (this.isStreaming) return;

    const messagesContainer = document.getElementById('ai-messages');
    if (!messagesContainer) return;

    this.addMessage('user', message);
    const assistantMsg = this.addMessage('assistant', '', true);

    this.isStreaming = true;

    try {
      const stream = await api.streamChat(
        message,
        scanId,
        null,
        null,
        this.conversationHistory
      );

      const reader = stream.getReader();
      const decoder = new TextDecoder();
      let fullResponse = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6);
            if (data === '[DONE]') {
              break;
            }
            fullResponse += data;
            assistantMsg.textContent = fullResponse;
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
          }
        }
      }

      this.conversationHistory.push({ role: 'user', content: message });
      this.conversationHistory.push({ role: 'assistant', content: fullResponse });

      if (this.conversationHistory.length > 20) {
        this.conversationHistory = this.conversationHistory.slice(-20);
      }

    } catch (error) {
      assistantMsg.textContent = 'Error: ' + error.message;
      assistantMsg.classList.add('error');
    } finally {
      this.isStreaming = false;
    }
  },

  addMessage(role, content, streaming = false) {
    const messagesContainer = document.getElementById('ai-messages');
    const msg = document.createElement('div');
    msg.className = `message ${role}${streaming ? ' streaming' : ''}`;
    msg.textContent = content;
    messagesContainer.appendChild(msg);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    return msg;
  },

  clearHistory() {
    this.conversationHistory = [];
    const messagesContainer = document.getElementById('ai-messages');
    if (messagesContainer) {
      messagesContainer.innerHTML = `
        <div class="message assistant">
          History cleared. What would you like to know?
        </div>
      `;
    }
  },

  sendToChat(text) {
    const input = document.getElementById('ai-input');
    if (input) {
      input.value = text;
      input.focus();
    }
  },
};

document.addEventListener('DOMContentLoaded', () => aiModule.init());
window.aiModule = aiModule;
