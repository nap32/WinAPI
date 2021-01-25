#pragma once
#include<Windows.h>
#include<tchar.h>
#include<WtsApi32.h>
#include<sddl.h>
#include<stdio.h>
#include"sedebugprivilege.h"

#pragma comment(lib, "wtsapi32")
#pragma	comment(lib, "Advapi32")

#define MAX_ACCOUNTNAME_LEN 1024
#define MAX_DOMAINNAME_LEN 1024

int main();