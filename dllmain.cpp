#include "pch.h"

namespace
{
	constexpr int CurlOptUrl = 10002;

	constexpr std::array<std::string_view, 2> RedirectedDomains = { "epicgames.com", "epicgames.net" };

	template <std::size_t Size>
	consteval std::array<std::int16_t, Size / 3> ParseSignature(const char (&text)[Size])
	{
		const auto nibble = [](char digit) -> int
		{
			if (digit >= '0' && digit <= '9')
				return digit - '0';
			if (digit >= 'A' && digit <= 'F')
				return digit - 'A' + 10;
			throw "Invalid signature digit";
		};

		if (Size % 3 != 0)
			throw "Invalid signature length";

		std::array<std::int16_t, Size / 3> bytes{};
		for (std::size_t index = 0; index < bytes.size(); ++index)
		{
			const auto high = text[index * 3];
			const auto low = text[index * 3 + 1];
			if (index + 1 < bytes.size() && text[index * 3 + 2] != ' ')
				throw "Invalid signature separator";

			bytes[index] = high == '?' && low == '?' ? -1 : static_cast<std::int16_t>(nibble(high) << 4 | nibble(low));
		}

		return bytes;
	}

	constexpr auto CurlEasySetoptSignature = ParseSignature("89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC ?? 48 85 C9 75 ?? 8D 41 2B 48 83 C4 ?? C3 4C 8D 44 24 ?? E8");

	constexpr ULONGLONG SignatureTimeout = 60000;

	constexpr std::wstring_view ConsoleName = L"CN-Redirect";

	struct VersionBlockHeader
	{
		WORD Length;
		WORD ValueLength;
		WORD Type;
	};

	struct VersionBlock
	{
		std::size_t Size;
		std::wstring_view Key;
		std::span<const std::uint8_t> Value;
		std::span<const std::uint8_t> Children;
	};

	using CurlEasySetoptFn = int (*)(void*, int, void*);
	CurlEasySetoptFn CurlEasySetoptOriginal = nullptr;

	FILE* ConsoleStream = nullptr;

	void Log(const char* format, ...)
	{
		if (!ConsoleStream)
			return;

		va_list arguments;
		va_start(arguments, format);
		std::vfprintf(ConsoleStream, format, arguments);
		va_end(arguments);
	}

	constexpr std::size_t AlignVersionOffset(std::size_t offset)
	{
		return (offset + 3) & ~std::size_t{ 3 };
	}

	std::wstring_view ReadWideString(std::span<const std::uint8_t> data)
	{
		const auto text = reinterpret_cast<const wchar_t*>(data.data());
		return { text, wcsnlen(text, data.size() / sizeof(wchar_t)) };
	}

	std::optional<VersionBlock> ReadVersionBlock(std::span<const std::uint8_t> data)
	{
		VersionBlockHeader header{};
		if (data.size() < sizeof(header))
			return std::nullopt;

		std::memcpy(&header, data.data(), sizeof(header));
		if (header.Length < sizeof(header) || header.Length > data.size())
			return std::nullopt;

		const auto block = data.first(header.Length);
		const auto key = ReadWideString(block.subspan(sizeof(header)));
		const auto valueOffset = (std::min)(AlignVersionOffset(sizeof(header) + (key.size() + 1) * sizeof(wchar_t)), block.size());
		const auto valueSize = (std::min)(header.Type == 1 ? header.ValueLength * sizeof(wchar_t) : header.ValueLength, block.size() - valueOffset);
		const auto childrenOffset = (std::min)(AlignVersionOffset(valueOffset + valueSize), block.size());
		return VersionBlock{ header.Length, key, block.subspan(valueOffset, valueSize), block.subspan(childrenOffset) };
	}

	std::optional<VersionBlock> FindVersionChild(const VersionBlock& parent, std::wstring_view key)
	{
		for (auto children = parent.Children; const auto child = ReadVersionBlock(children); children = children.subspan((std::min)(AlignVersionOffset(child->Size), children.size())))
		{
			if (child->Key == key)
				return child;
		}

		return std::nullopt;
	}

	std::wstring_view FindProductVersion()
	{
		const auto module = GetModuleHandleW(nullptr);
		const auto resource = FindResourceW(module, MAKEINTRESOURCEW(VS_VERSION_INFO), RT_VERSION);
		const auto data = resource ? static_cast<const std::uint8_t*>(LockResource(LoadResource(module, resource))) : nullptr;
		if (!data)
			return {};

		const auto root = ReadVersionBlock({ data, SizeofResource(module, resource) });
		const auto strings = root ? FindVersionChild(*root, L"StringFileInfo") : std::nullopt;
		const auto table = strings ? ReadVersionBlock(strings->Children) : std::nullopt;
		const auto product = table ? FindVersionChild(*table, L"ProductVersion") : std::nullopt;
		return product ? ReadWideString(product->Value) : std::wstring_view{};
	}

	std::wstring ConsoleTitle()
	{
		const auto version = FindProductVersion();
		if (version.empty())
			return std::wstring(ConsoleName);

		return std::format(L"{} | {}", ConsoleName, version);
	}

	bool IsRedirectedHost(std::string_view host)
	{
		return std::ranges::any_of(RedirectedDomains, [host](std::string_view domain)
		{
			if (host.size() < domain.size())
				return false;

			const auto offset = host.size() - domain.size();
			return _strnicmp(host.data() + offset, domain.data(), domain.size()) == 0 && (offset == 0 || host[offset - 1] == '.');
		});
	}

	std::optional<std::string> RedirectUrl(std::string_view url)
	{
		const auto scheme = url.find("://");
		if (scheme == std::string_view::npos)
			return std::nullopt;

		const auto authority = url.substr(scheme + 3);
		if (!IsRedirectedHost(authority.substr(0, authority.find_first_of(":/?#"))))
			return std::nullopt;

		std::string redirected(Configuration::Redirect);
		if (const auto path = authority.find_first_of("/?#"); path != std::string_view::npos)
			redirected += authority.substr(path);

		return redirected;
	}

	int CurlEasySetoptHook(void* handle, int option, void* parameter)
	{
		if (option == CurlOptUrl && parameter)
		{
			const auto url = static_cast<const char*>(parameter);
			if (auto redirected = RedirectUrl(url))
			{
				Log("%s -> %s\n", url, redirected->c_str());
				return CurlEasySetoptOriginal(handle, option, redirected->data());
			}
		}

		return CurlEasySetoptOriginal(handle, option, parameter);
	}

	std::uint8_t* FindCurlEasySetopt()
	{
		const auto image = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
		const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(image + reinterpret_cast<const IMAGE_DOS_HEADER*>(image)->e_lfanew);
		const auto imageEnd = image + headers->OptionalHeader.SizeOfImage;
		const auto matches = [](std::uint8_t byte, std::int16_t expected) { return expected < 0 || byte == expected; };

		constexpr DWORD Executable = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

		MEMORY_BASIC_INFORMATION region{};
		for (auto address = image; address < imageEnd && VirtualQuery(address, &region, sizeof(region)); address = static_cast<std::uint8_t*>(region.BaseAddress) + region.RegionSize)
		{
			if (region.State != MEM_COMMIT || !(region.Protect & Executable) || (region.Protect & PAGE_GUARD))
				continue;

			const auto begin = static_cast<std::uint8_t*>(region.BaseAddress);
			const auto end = (std::min)(begin + region.RegionSize, imageEnd);
			if (const auto match = std::search(begin, end, CurlEasySetoptSignature.begin(), CurlEasySetoptSignature.end(), matches); match != end)
				return match;
		}

		return nullptr;
	}

	std::uint8_t* WaitForCurlEasySetopt()
	{
		const auto deadline = GetTickCount64() + SignatureTimeout;
		do
		{
			if (const auto address = FindCurlEasySetopt())
				return address;

			Sleep(100);
		} while (GetTickCount64() < deadline);

		return nullptr;
	}

	DWORD WINAPI Initialize(LPVOID)
	{
		if constexpr (Configuration::Console)
		{
			AllocConsole();
			SetConsoleTitleW(ConsoleTitle().c_str());
			if (fopen_s(&ConsoleStream, "CONOUT$", "w") == 0)
				setvbuf(ConsoleStream, nullptr, _IONBF, 0);
		}

		Log("Redirect: %.*s\n", static_cast<int>(Configuration::Redirect.size()), Configuration::Redirect.data());

		const auto target = WaitForCurlEasySetopt();
		if (!target)
		{
			Log("curl_easy_setopt not found\n");
			return 1;
		}

		auto status = MH_Initialize();
		if (status == MH_OK)
			status = MH_CreateHook(target, reinterpret_cast<void*>(&CurlEasySetoptHook), reinterpret_cast<void**>(&CurlEasySetoptOriginal));
		if (status == MH_OK)
			status = MH_EnableHook(target);

		Log("curl_easy_setopt at %p: %s\n", static_cast<void*>(target), MH_StatusToString(status));
		return status == MH_OK ? 0 : 1;
	}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(module);
		if (const auto thread = CreateThread(nullptr, 0, Initialize, nullptr, 0, nullptr))
			CloseHandle(thread);
	}

	return TRUE;
}
