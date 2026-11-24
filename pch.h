#pragma once

#include <Windows.h>
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <format>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include "MinHook.h"

namespace Configuration
{
	inline constexpr std::string_view Redirect = "http://127.0.0.1:3551";
	inline constexpr bool Console = true;
}
