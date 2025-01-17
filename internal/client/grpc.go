package client

import (
	"log"

	adminv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/admin"
	authv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/auth"
	userv1 "github.com/mohamedfawas/rmshop-proto/gen/v1/user"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure" // used for creating non encrypted connection
)

type GrpcClients struct {
	Auth  authv1.AuthServiceClient
	Admin adminv1.AdminServiceClient
	User  userv1.UserServiceClient
}

func NewGrpcClients(authAddr, adminAddr, userAddr string) (*GrpcClients, error) {
	// Initialize a connection to the Auth service
	// `grpc.NewClient` creates a new gRPC channel (connection) to the service address
	// `WithTransportCredentials(insecure.NewCredentials())` disables transport layer security (TLS)
	// making this an insecure connection (use this method only for local dev or testing).
	authConn, err := grpc.NewClient(authAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("failed to establish grpc connection to authentication service : %v", err)
		return nil, err
	}

	// Initialize Admin Service Client
	adminConn, err := grpc.NewClient(adminAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("failed to establish grpc connection to admin service : %v", err)
		return nil, err
	}

	// Initialize User Service Client
	userConn, err := grpc.NewClient(userAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("failed to establish grpc connection to user service : %v", err)
		return nil, err
	}

	// Create and return GrpcClients instance
	return &GrpcClients{
		Auth:  authv1.NewAuthServiceClient(authConn),
		Admin: adminv1.NewAdminServiceClient(adminConn),
		User:  userv1.NewUserServiceClient(userConn),
	}, nil
}
