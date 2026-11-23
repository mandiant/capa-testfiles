
#include <windows.h>

int main(void)
{
    SC_HANDLE scm = OpenSCManagerA(
        NULL,
        NULL,
        SC_MANAGER_CONNECT
    );

    if (scm == NULL) {
        return 1;
    }

    const char *services[] = {
        "veeam",
        "dbeng50",
        "vss"
    };

    for (int i = 0; i < 3; i++) {
        SC_HANDLE service = OpenServiceA(
            scm,
            services[i],
            SERVICE_QUERY_STATUS
        );

        if (service != NULL) {
            SERVICE_STATUS status;
            QueryServiceStatus(service, &status);
            CloseServiceHandle(service);
        }
    }

    CloseServiceHandle(scm);
    return 0;
}