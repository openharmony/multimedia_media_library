EXPORT static std::string GetCachePath(const std::string& path);
EXPORT static bool IsLivePhoto(const std::string& path);
EXPORT static bool IsValidPath(const std::string& path);
EXPORT static int32_t GetExtraDataLen(const std::string& extraDataPath, const std::string& videoPath,
    uint32_t frameIndex, off_t& fileSize);
EXPORT static uint32_t GetFrameIndex(int64_t time, const UniqueFd& fd);