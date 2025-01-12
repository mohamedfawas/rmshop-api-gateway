package client

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	adminv1 "github.com/mohamedfawas/rmshop-proto/gen/admin/v1"
	authv1 "github.com/mohamedfawas/rmshop-proto/gen/auth/v1"
	userv1 "github.com/mohamedfawas/rmshop-proto/gen/user/v1"
)

type GRPCClients struct {
	AuthClient  authv1.AuthServiceClient
	UserClient  userv1.UserServiceClient
	AdminClient adminv1.AdminServiceClient
	conns       []*grpc.ClientConn
}

func NewGRPCClients(authURL, userURL, adminURL string) (*GRPCClients, error) {
	var conns []*grpc.ClientConn

	// Connect to Auth Service
	authConn, err := grpc.Dial(authURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	conns = append(conns, authConn)

	// Connect to User Service
	userConn, err := grpc.Dial(userURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cleanup(conns)
		return nil, err
	}
	conns = append(conns, userConn)

	// Connect to Admin Service
	adminConn, err := grpc.Dial(adminURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cleanup(conns)
		return nil, err
	}
	conns = append(conns, adminConn)

	return &GRPCClients{
		AuthClient:  authv1.NewAuthServiceClient(authConn),
		UserClient:  userv1.NewUserServiceClient(userConn),
		AdminClient: adminv1.NewAdminServiceClient(adminConn),
		conns:       conns,
	}, nil
}

func (c *GRPCClients) Close() {
	cleanup(c.conns)
}

func cleanup(conns []*grpc.ClientConn) {
	for _, conn := range conns {
		conn.Close()
	}
}
