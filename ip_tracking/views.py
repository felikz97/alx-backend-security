from django.http import JsonResponse
from ratelimit.decorators import ratelimit

# Limit: 10 requests/min for authenticated, 5 requests/min for anonymous
@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', group='anon', block=True)
def login_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    return JsonResponse({'status': 'Login simulated'})
