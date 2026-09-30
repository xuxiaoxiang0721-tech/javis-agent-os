"""Read only terminal SSE metadata; never retain output text in accounting."""
import json


def inspect_sse(content):
    result = {'status': 'truncated', 'usage': None, 'model': None,
              'error_type': 'SubscriptionStreamTruncated'}
    terminal = False
    text = content.decode('utf-8').replace('\r\n', '\n').replace('\r', '\n')
    for frame in text.split('\n\n'):
        data = '\n'.join(line[5:].lstrip(' ') for line in frame.split('\n') if line.startswith('data:'))
        if not data or data == '[DONE]':
            continue
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError('invalid_subscription_event')
        kind = value.get('type')
        if kind in {'response.completed', 'response.failed', 'response.incomplete', 'error'}:
            if terminal:
                raise ValueError('multiple_subscription_terminal_events')
            terminal = True
            response = value.get('response') or {}
            if not isinstance(response, dict):
                raise ValueError('invalid_subscription_response')
            result['usage'] = response.get('usage') if isinstance(response.get('usage'), dict) else None
            result['model'] = response.get('model') if isinstance(response.get('model'), str) else None
            success = kind == 'response.completed' and response.get('status') == 'completed'
            result['status'] = 'completed' if success else 'failed' if kind in {'response.failed', 'error'} else 'incomplete'
            result['error_type'] = None if success else 'SubscriptionStreamFailed' if result['status'] == 'failed' else 'SubscriptionStreamIncomplete'
    return result
