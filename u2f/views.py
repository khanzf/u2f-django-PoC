from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.shortcuts import render
from u2f.forms import LoginPromptForm
from u2f.forms import KeyResponseForm

from django.contrib import auth
from u2flib_server import u2f_v2 as u2f

import json

# Create your views here.

def login(request):
    if request.method == 'POST':
        loginpromptform = LoginPromptForm(request.POST)
        if loginpromptform.is_valid():
            username = loginpromptform.cleaned_data['username']
            password = loginpromptform.cleaned_data['password']
            user = auth.authenticate(username=username, password=password)
            if user is not None:
#                auth.login(request, user)
                if user.u2f_keys.count() > 0:
                    print("There is a key registered")
                    request.session['authuser'] = user.pk;
                    request.session['backend'] = user.backend
                    return HttpResponseRedirect('/twofactor/')
                else:
                    print("Redirecting to Add_keyr")
                    print(user.backend)
                    auth.login(request, user)
                    return HttpResponseRedirect('/add_key/')

    loginpromptform = LoginPromptForm()
    context = {'loginprompt': loginpromptform}
    return render(request, 'u2f/login.html', context)

def add_key(request):

    if request.method == 'POST':
        # Add the key
        keyresponseform = KeyResponseForm(request.POST)
        if keyresponseform.is_valid():
            response = keyresponseform.cleaned_data['response']
            challenge = request.session['u2f_registration_challenge']
            print(challenge)
            del request.session['u2f_registration_challenge']
            device, attestation_cert = u2f.complete_register(challenge, response)
            request.user.u2f_keys.create(
                public_key=device['publicKey'],
                key_handle=device['keyHandle'],
                app_id=device['appId'],
            )
            print("%s\n\n\n%s" % (device, attestation_cert))
            return HttpResponseRedirect('/dashboard/')

    # Else if its a GET variable
    # Send them the request
    origin = '{scheme}://{host}'.format(
                scheme='https' if request.is_secure() else 'http',
                host=request.get_host(),
             )
    challenge = u2f.start_register(origin)
    request.session['u2f_registration_challenge'] = challenge
#    sign_requests = [u2f.start_authenticate(d.to_json()) for d in request.user.u2f_keys.all()]

    context = {'challenge': json.dumps(challenge)}
#               'sign_requests': sign_requests}

    return render(request, 'u2f/add_key.html', context)

def twofactor(request):
    print("All u2f keys")

    user = User.objects.get(pk=request.session['authuser'])
    print("The user is: %s" % user)
    challenges = [u2f.start_authenticate(u2f_key.to_json()) for u2f_key in user.u2f_keys.all()]

    if request.method == 'POST':
        u2f_response = KeyResponseForm(request.POST)

        if u2f_response.is_valid():
            device_response = u2f_response.cleaned_data['response']
            challenge = request.session['u2f_authentication_challenges'][0]

            device = user.u2f_keys.get() #key_handle=device_response['keyHandle'])
            print("Check this: %s" % device)

#            u2f_response_json = json.dumps(u2f_response.cleaned_data['response'])
            u2f_response_json = u2f_response.cleaned_data['response']

            login_counter, touch_asserted = u2f.verify_authenticate(device.to_json(), challenge, u2f_response_json,)
            print("Touch asserted: %s" % touch_asserted)
#            device.last_used_at = timezone.now()
#            device.save()
            del request.session['u2f_authentication_challenges']
            user.backend = request.session['backend']
            del request.session['backend']
            auth.login(request, user=user)
            return HttpResponseRedirect('/dashboard/')
    else:
        u2f_response = KeyResponseForm()
        print("The user is currently: %s" % user)
#        challenges = [user.u2f_keys.get().to_json()]
#        print(challenges)
        challenges = [u2f.start_authenticate(user.u2f_keys.get().to_json())]
        print(challenges)
        request.session['u2f_authentication_challenges'] = challenges
#        challenges = [u2f.start_authenticate(u2f_key.to_json()) for u2f_key in user.u2f_keys.all()]
        print("Final: %s" % str(json.dumps(challenges)))

        context = {'u2f_response': u2f_response,
                   'challenges': json.dumps(challenges)}
        return render(request, 'u2f/twofactor.html', context)

def dashboard(request):
    context = {}
    return render(request, 'u2f/dashboard.html', context)
