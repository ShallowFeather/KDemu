#include "Elevator.h"

#include <Windows.h>

bool KDemu::Elevator::CanElevate() {
	HANDLE hToken = nullptr;
	TOKEN_ELEVATION_TYPE tokenType = TokenElevationTypeLimited;
	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,
	                      &hToken))
		return false;
	DWORD len;
	GetTokenInformation(hToken, TokenElevationType, &tokenType,
	                    sizeof(TOKEN_ELEVATION_TYPE), &len);
	CloseHandle(hToken);
	return tokenType == TokenElevationTypeLimited;
}
