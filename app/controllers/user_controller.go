package controllers

import (
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kooroshh/fiber-boostrap/app/models"
	"github.com/kooroshh/fiber-boostrap/app/repository"
	"github.com/kooroshh/fiber-boostrap/pkg/jwt_token"
	"github.com/kooroshh/fiber-boostrap/pkg/response"
	"golang.org/x/crypto/bcrypt"
)

func Register(ctx *fiber.Ctx) error {
	user := new(models.User)
	err := ctx.BodyParser(user)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}
	err = user.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		errResponse := fmt.Errorf("failed to encrypt the password: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}
	user.Password = string(hashPassword)

	err = repository.InsertNewUser(ctx.Context(), user)
	if err != nil {
		errResponse := fmt.Errorf("failed to insert new user: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	resp := user
	resp.Password = ""
	return response.SendSuccessResponse(ctx, resp)
}

func Login(ctx *fiber.Ctx) error {
	// parsing req dan validate req
	var (
		loginReq = new(models.LoginRequest)
		resp     = models.LoginResponse{}
		now      = time.Now()
	)
	err := ctx.BodyParser(loginReq)
	if err != nil {
		errResponse := fmt.Errorf("failed to parse request: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	err = loginReq.Validate()
	if err != nil {
		errResponse := fmt.Errorf("failed to validate request: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusBadRequest, errResponse.Error(), nil)
	}

	user, err := repository.GetUserByUsername(ctx.Context(), loginReq.Username)
	if err != nil {
		//errResponse := fmt.Errorf("failed to get username: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, "username/password wrong", nil)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		//errResponse := fmt.Errorf("Password not match: %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusNotFound, "username/password wrong", nil)
	}

	token, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate token %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	refreshToken, err := jwt_token.GenerateToken(ctx.Context(), user.Username, user.Fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate refresh token %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}

	userSession := &models.UserSession{
		UserID:              user.ID,
		Token:               token,
		RefreshToken:        refreshToken,
		TokenExpired:        now.Add(jwt_token.MapTypeToken["token"]),
		RefreshTokenExpired: now.Add(jwt_token.MapTypeToken["refresh_token"]),
	}
	err = repository.InsertNewUserSession(ctx.Context(), userSession)
	if err != nil {
		//errResponse := fmt.Errorf("failed insert user session %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "Something error", nil)
	}

	resp.Username = user.Username
	resp.Fullname = user.Fullname
	resp.Token = token
	resp.RefreshToken = refreshToken
	return response.SendSuccessResponse(ctx, resp)
}

func Logout(ctx *fiber.Ctx) error {
	token := ctx.Get("Authorization")
	err := repository.DeleteUserSessionByToken(ctx.Context(), token)
	if err != nil {
		errResponse := fmt.Errorf("failed to delete user session %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "Something error", nil)
	}
	return response.SendSuccessResponse(ctx, nil)
}

func RefreshToken(ctx *fiber.Ctx) error {

	now := time.Now()
	refreshToken := ctx.Get("Authorization")
	username := ctx.Locals("username").(string)
	fullname := ctx.Locals("full_name").(string)

	token, err := jwt_token.GenerateToken(ctx.Context(), username, fullname, "token", now)
	if err != nil {
		errResponse := fmt.Errorf("failed to generate token %v", err)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, errResponse.Error(), nil)
	}
	err = repository.UpdateUserSessionToken(ctx.Context(), token, now.Add(jwt_token.MapTypeToken["token"]), refreshToken)
	if err != nil {
		errResponse := fmt.Errorf("failed to update user session %v", err)
		fmt.Println(errResponse)
		return response.SendFailureResponse(ctx, fiber.StatusInternalServerError, "Something error", nil)
	}
	return response.SendSuccessResponse(ctx, fiber.Map{
		"token": token,
	})
}
