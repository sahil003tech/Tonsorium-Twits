from django.contrib.auth import authenticate, login, get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from django.shortcuts import reverse
from django.utils.decorators import method_decorator
from django.views.generic import CreateView, FormView, DetailView, View, UpdateView
from django.views.generic.edit import FormMixin
from django.http import HttpResponse
from django.shortcuts import render, redirect
import is_safe_url
from django.utils.safestring import mark_safe
from .models import Client, Store, Employee
from payment.models import Salarie

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.core.mail import EmailMessage
from django.conf import settings
from .utils import generate_token
from django.contrib.auth.models import User


class ActivateAccount(View):
    def get(self, request, uidb64, token, status):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            if user is not None:
                if status == 'store':
                    obj = Store.objects.filter(user=user).first()
                elif status == 'employee':
                    obj = Employee.objects.filter(user=user).first()
                else:
                    obj = Client.objects.filter(user=user).first()
        except Exception:
            user = None

        if user is not None and generate_token.check_token(user, token):
            obj.active = True
            obj.save()
            messages.info(request, 'Account Verified.Please login')
            return redirect('login')

        return render(request, 'activate_fail.html', status=401)



def RegisterUser(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        contact = request.POST.get('contact')
        password = request.POST.get('password')

        status = request.POST.get('status')
        print("===>>>>>", email,contact,password)
        try:
            print("---- user")
            User.objects.create(username=email,email=email,password=password)
        except:
            messages.info(request, "User already exists")

        user = User.objects.filter(email=email).first()
        if user:
            print(user, user.pk, urlsafe_base64_encode(force_bytes(user.pk)))
            if status == 'store':
                obj = Store.objects.create(user=user, contact=contact, active=False)
                # send_activation(request, user, status)
            elif status == 'employee':
                obj = Employee.objects.create(user=user, contact=contact, active=False)
                # send_activation(request, user, status)
            else:
                obj = Client.objects.create(user=user, contact=contact, active=False)
                # send_activation(request, user, status)

        messages.info(request, "Please Login Using email id and password")

        return redirect('login')
    return render(request, 'register.html')


def LoginUser(request):
    if request.method == 'POST':
        request.session['status'] = None
        status = request.POST.get('status')
        email = request.POST.get('email')
        password = request.POST.get('password')
        flag = 0
        user = User.objects.filter(username=email).first()
        print("====?>>>> user : ",user)
        if status == 'store':
            obj = Store.objects.filter(user=user).first()
            try:
                if user and not request.user.is_authenticated:
                        login(request, user)
                        print("user ============",user)
                        request.user = user
                        request.session['status'] = True
                        context = {
                            'user': request.user
                        }

                        return render(request,'dashboard.html',context= context)
                else:
                    messages.info(request, "Invalid Credentials.Make sure you have already registered.")
                    return redirect('login')
            except:
                messages.info(request, "Make sure you have already registered and activated your account")
                return redirect('login')

        elif status == 'employee':
            obj = Employee.objects.filter(user=user).first()
            print(obj)
            try:
                if user and not request.user.is_authenticated:
                    login(request, user)
                    print("user succesful", user)
                    request.session['status'] = True
                    request.user = user


                    context = {
                        'user': request.user
                    }


                    return render(request,'employee.html',context=context)
                else:
                    print('==================================')
                    messages.info(request, "Invalid Credentials.Make sure you have already registered.")
                    return redirect('login')
            except:
                messages.info(request, "Make sure you have already registered and activated your account")
                return redirect('login')
        else:
            print("===>>> else")
            obj = Client.objects.filter(user=user).first()
            print("===>>> obj : ",obj.active)
            try:
                if user and not request.user.is_authenticated:
                        login(request, user)
                        request.user = user
                        return redirect('home')
                else:
                    messages.info(request, "Invalid Credentials.Make sure you have already registered.")
                    return redirect('login')
            except:
                messages.info(request, "Make sure you have already registered and activated your account")
                return redirect('login')
    return render(request, 'login.html')


def dashboard(request):
    emp_name = None
    emp_info = None
    sal_info = None
    if request.method == 'POST':
        emp_name = request.POST.get('emp_name')
        print(emp_name)
        emp_info = Employee.objects.filter(name=emp_name).values()
     ##   sal_info = Salarie.objects.filter(user=emp_name).values()
    print("****************",sal_info)

    print("++++++++++++++++++",emp_info)

    new_dict = {}
    for item in emp_info:
        new_dict = item

    print("________",new_dict)

    user = request.user
    store = Store.objects.filter(user=user).first()
    store_name = store.name

    employees_ = Employee.objects.all()
    print(employees_)
    employees = []
    for i in employees_:
      if i.store == store:
        employees.append(i.name)

    context = {
        'user':user,
        'store':store_name,
        'employee':employees_,


        'emp_name': emp_name,
        'emp_info':new_dict,
        'employees': employees,
        'sal_info': sal_info,
    }
    return render(request, 'dashboard.html', context=context)


def Logout_view(request):
    logout(request)
    return redirect("home")


def password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        newpass = request.POST.get('newpass')
        try:
            obj = User.objects.filter(username=email).first()
            obj.set_password(newpass)
            obj.save()
            messages.info(request, 'Password successfully changed,Please login now')
            return redirect('login')
        except:
            messages.info(request, "Account with this email does not exists.Make a new one")
            return redirect('password')

    return render(request, 'password_change.html')
