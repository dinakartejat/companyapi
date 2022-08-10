class AuthenticationController < ApplicationController
  before_action :authorize_request, except: :login

    # POST /auth/login
    def login
      @user = User.find_by_email(params[:email])
      if @user&.authenticate(params[:password])
        token = JsWebToken.encode(user_id: @user.id)
        time = Time.now + 24.hours.to_i
        render json: { token: token, exp: time.strftime("%m-%d-%Y %H:%M"),
                       username: @user.username }, status: :ok
      else
        render json: { error: 'unauthorized' }, status: :unauthorized
      end
    end

    private

    def login_params
      params.permit(:email, :password)
    end
end
# class AuthenticationController < ApplicationController
#   skip_before_action :authenticate_request
#   def login
#     @user = User.find_by_email(params[:email])
#     if @user&.authenticate(params[:password])
#       token = jwt_encode(user_id: @user.id)
#       render json: { token: token }, status: :ok
#     else
#       render json: { error: 'unauthorized' }, status: :unauthorized
#     end
#   end
# end
