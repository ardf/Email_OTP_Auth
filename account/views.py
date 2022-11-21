from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.exceptions import APIException
from rest_framework.views import APIView
from rest_framework.response import Response
from django.core.mail import send_mail
import pyotp
from .models import User
# Create your views here.
class UserView(APIView):
    permission_classes = (IsAuthenticated,)
    def get(self, request):
        return Response(data={"message": "Welcome"},status=200)

class OTPLoginView(APIView):
    """
    This API is used to generate auth token for an user post OTP validation.
    """
    permission_classes = (AllowAny,)
    def get_otp(self, request):
        data = request.data
        email = data.get("email")
        user = User.objects.filter(email=email).first()
        if user:
            otp_key = user.otp_key
            otp = pyotp.TOTP(otp_key, interval=300).now()
            print(otp) 
            response = self.send_otp(email, otp) 
        return Response(data={"message": "OTP sent"})

    def send_otp(self, email, otp):
        response = send_mail(
            subject='OTP for Curus Authentication',
            message=f'Your OTP for CURUS Authentication is {otp}',
            from_email='ruyefadf@gmail.com',
            recipient_list=[email, ],
            fail_silently=False,
            )
        print(response)
        return response

    def post(self, request):
        data = request.data
        email = data.get("email")
        action = request.query_params.get("action")
        if action == "requestOTP":
            return self.get_otp(request)
        # Get User instance
        user = User.objects.filter(email=email).last()
        if user:
            otp = data.get("otp")
            if pyotp.TOTP(user.otp_key, interval=300).verify(otp):
                # Generate a token and send it in response
                token = RefreshToken.for_user(user)
                return Response(data={
                    "access": str(token.access_token),
                    "refresh": str(token)
                })
            else:
                return Response(data={"message":"Invalid OTP"},status=404)
        else:
            return Response(data={"message":"User not found"},status=404)