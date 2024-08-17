static const mode_t CHOWN_RO_USR_GRP = 0644;
static const uint32_t BUFFER_LENGTH = 1024;

const string LIVE_PHOTO_CINEMAGRAPH_INFO = "CinemagraphInfo";
const string LIVE_PHOTO_VIDEO_INFO_METADATA = "VideoInfoMetadata";
const string LIVE_PHOTO_SIGHT_TREMBLE_META_DATA = "SightTrembleMetadata";
const string LIVE_PHOTO_VERSION_AND_FRAME_NUM = "VersionAndFrameNum";

const uint32_t LIVE_PHOTO_VERSION = 3; // 动态照片版本

string GetVersionPositionTag(uint32_t frame, const string& data = "")
{
    string buffer;
    if (data.size() != 0) {
        buffer += data.substr(0, data.find('f'));
    } else {
        buffer += "v3_f";
    }
    buffer += to_string(frame);
    uint32_t left = LIVE_TAG_LEN - buffer.length();
    for (uint32_t i = 0; i < left; i++) {
        buffer += " ";
    }
    return buffer;
}

string GetDurationTag(const string& data = "")
{
    string buffer;
    if (data.size() != 0) {
        buffer += data;
    } else {
        buffer += "0:0";
    }
    uint32_t left = PLAY_INFO_LEN - buffer.length();
    for (uint32_t i = 0; i < left; i++) {
        buffer += " ";
    }
    return buffer;
}

string GetDurationTag(const string& data = "")
{
    string buffer;
    if (data.size() != 0) {
        buffer += data;
    } else {
        buffer += "0:0";
    }
    uint32_t left = PLAY_INFO_LEN - buffer.length();
    for (uint32_t i = 0; i < left; i++) {
        buffer += " ";
    }
    return buffer;
}

string GetVideoInfoTag(off_t fileSize)
{
    string buffer = "LIVE_" + to_string(fileSize);
    uint32_t left = VERSION_TAG_LEN - buffer.length();
    for (uint32_t i = 0; i < left; i++) {
        buffer += " ";
    }
    return buffer;
}

off_t GetFileSize(const UniqueFd& fd)
{
    struct stat st;
    if (fstat(fd.Get(), &st) != E_OK) {
        MEDIA_ERR_LOG("Failed to get file size");
        return E_ERR;
    }
    return st.st_size;
}

off_t GetFileSize(const string& path)
{
    struct stat st;
    if (stat(path.c_str(), &st) != E_OK) {
        MEDIA_ERR_LOG("Failed to get file size");
        return E_ERR;
    }
    return st.st_size;
}

int32_t SendContentTofile(const UniqueFd& destFd, const UniqueFd& srcFd, off_t& offset)
{
    if (sendfile(destFd.Get(), srcFd.Get(), &offset, GetFileSize(srcFd)) == E_ERR) {
        return E_ERR;
    }
    return E_OK;
}

int32_t WriteContentTofile(const UniqueFd& destFd, const UniqueFd& srcFd)
{
    char buffer[BUFFER_LENGTH];
    ssize_t bytesRead, bytesWritten;
    while ((bytesRead = read(srcFd.Get(), buffer, BUFFER_LENGTH)) > 0) {
        bytesWritten = write(destFd.Get(), buffer, bytesRead);
        if (bytesWritten != bytesRead) {
            return E_ERR;
        }
    }
    return E_OK;
}

int32_t AddStringTofile(const UniqueFd& destFd, const string& temp)
{
    if (write(destFd.Get(), temp.c_str(), temp.size()) == E_ERR) {
        return E_ERR;
    }
    return E_OK;
}

string GetExtraData(const UniqueFd& fd, off_t fileSize, off_t offset, off_t needSize)
{
    off_t readPosition = fileSize > offset ? fileSize - offset : 0;
    if (lseek(fd.Get(), readPosition, SEEK_SET) == E_ERR) {
        MEDIA_ERR_LOG("Failed to lseek extra file");
        return "";
    }
    char buffer[needSize + 1];
    if (read(fd.Get(), buffer, needSize) < 0) {
        MEDIA_ERR_LOG("Failed to read extra file");
        return "";
    }
    return string(buffer);
}

int32_t ReadExtraDataFile(const string extraPath, map<string, string>& extraData)
{
    UniqueFd fd(open(extraPath.c_str(), O_RDONLY));
    if (fd.Get() == E_ERR) {
        MEDIA_ERR_LOG("Failed to open extra file");
        return E_ERR;
    }
    uint32_t version{0};
    uint32_t frameIndex{0};
    bool hasCinemagraghInfo{false};
    if (MovingPhotoFileUtils::GetversionAndFrameNum(fd.Get(), version, frameIndex, hasCinemagraghInfo) != E_OK) {
        return E_ERR;
    }
    off_t fileSize = GetFileSize(fd);
    extraData[LIVE_PHOTO_VIDEO_INFO_METADATA] = GetExtraData(fd, fileSize, LIVE_TAG_LEN, LIVE_TAG_LEN);
    extraData[LIVE_PHOTO_SIGHT_TREMBLE_META_DATA] = GetExtraData(fd, fileSize, LIVE_TAG_LEN + PLAY_INFO_TAG,
        PLAY_INFO_TAG);
    if (version == LIVE_PHOTO_VERSION) {
        extraData[LIVE_PHOTO_VERSION_AND_FRAME_NUM] = GetExtraData(fd, fileSize, MIN_STANDARD_SIZE, VERSION_TAG_LEN);
        if (hasCinemagraghInfo) {
            extraData[LIVE_PHOTO_CINEMAGRAPH_INFO] = GetExtraData(fd, fileSize, fileSize, fileSize - MIN_STANDARD_SIZE);
        }
    } else {
        if (hasCinemagraghInfo) {
            extraData[LIVE_PHOTO_CINEMAGRAPH_INFO] = GetExtraData(fd, fileSize, fileSize,
                fileSize - LIVE_TAG_LEN - PLAY_INFO_TAG);
        }
    }
    return E_OK;
}

bool MovingPhotoFileUtils::IsValidPath(const std::string& path)
{
    return access(path.c_str(), F_OK) == E_OK;
}

int32_t WriteExtraData(const string& extraPath, const UniqueFd& livePhotoFd, const UniqueFd& videoFd,
    uint32_t frameIndex)
{
    map<string, string> extraData;
    if (MovingPhotoFileUtils::IsValidPath(extraPath)) {
        if(ReadExtraDataFile(extraPath, extraData) == E_ERR) {
            return E_ERR;
        }
        if (AddStringTofile(livePhotoFd, extraData[LIVE_PHOTO_CINEMAGRAPH_INFO]) == E_ERR) {
            MEDIA_ERR_LOG("Failed to add cinemagraph info");
            return E_ERR;
        }
    }

    if (AddStringTofile(livePhotoFd, GetVersionPositionTag(frameIndex,
        extraData[LIVE_PHOTO_VIDEO_INFO_METADATA])) == E_ERR) {
        MEDIA_ERR_LOG("Failed to add video and metadata");
        return E_ERR;
    }
    if (AddStringTofile(livePhotoFd, GetDurationTag(extraData[LIVE_PHOTO_SIGHT_TREMBLE_META_DATA])) == E_ERR) {
        MEDIA_ERR_LOG("Failed to add duration tag");
        return E_ERR;
    }
    if (AddStringTofile(livePhotoFd, GetDurationTag(GetFileSize(videoFd) + VERSION_TAG_LEN +
        extraData[LIVE_PHOTO_VERSION_AND_FRAME_NUM])) == E_ERR) {
        MEDIA_ERR_LOG("Failed to add version and frame num");
        return E_ERR;
    }
    return E_OK;
}

int32_t MovingPhotoFileUtils::GetExtraDataLen(const string& extraPath, const string& videoPath
    uint32_t frameIndex, off_t& fileSize)
{
    if (MovingPhotoFileUtils::IsValidPath(extraPath)) {
        fileSize = GetFileSize(extraPath);
    } else {
        UniqueFd extraDataFd(open(extraPath.c_str(), O_WRONLY | O_CREAT, CHOWN_RO_USR_GRP));
        if (AddStringTofile(livePhotoFd, GetVersionPositionTag(frameIndex)) == E_ERR) {
            MEDIA_ERR_LOG("Failed to add video and metadata");
            return E_ERR;
        }
        if (AddStringTofile(livePhotoFd, GetDurationTag() == E_ERR)) {
            MEDIA_ERR_LOG("Failed to add duration tag");
            return E_ERR;
        }
        if (AddStringTofile(livePhotoFd, GetDurationTag(GetFileSize(videoFd) + VERSION_TAG_LEN)) == E_ERR) {
            MEDIA_ERR_LOG("Failed to add version and frame num");
            return E_ERR;
        }
        fileSize = MIN_STANDARD_SIZE;
    }
    return E_OK;
}

int32_t MergeFile(const UniqueFd& imageFd, const UniqueFd& videoFd, const UniqueFd& livePhotoFd,
    const string& extraPath, uint32_t frameIndex)
{
    off_t offset{0};
    if (SendContentTofile(livePhotoFd, imageFd, offset) == E_ERR) {
        MEDIA_ERR_LOG("Failed to write image");
        return E_ERR;
    }
    if (WriteContentTofile(livePhotoFd, videoFd) == E_ERR) {
        MEDIA_ERR_LOG("Failed to write video");
        return E_ERR;
    }
    if (WriteExtraData(extraPath, livePhotoFd, videoFd, frameIndex) == E_ERR) {
        MEDIA_ERR_LOG("Failed to write extra data");
        return E_ERR;
    }
    return E_OK;
}

uint32_t MovingPhotoFileUtils::GetFrameIndex(int64_t time, const UniqueFd& fd)
{
    uint32_t index{0};
    shared_ptr<AVMetadataHelper> avMetadataHelper = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (avMetadataHelper->SetSource(fd.Get(), 0, static_cast<int64_t>(GetFileSize(fd)), AV_META_USAGE_ONLY)
        != E_OK) {
        MEDIA_ERR_LOG("Failed to set source");
        return index;
    }
    if (avMetadataHelper->GetFrameIndexByTime(time, index) != E_OK) {
        MEDIA_ERR_LOG("Failed to get frame index");
    }
    return index;
}

const string MovingPhotoFileUtils::ConvertToLivePhoto(const string& path, int64_t coverPosition)
{
    string videoPath = MediaFileUtils::GetmovingPhotoVideoPath(path);
    string cachePath = GetCachePath(path);
    string extraPath = GetmovingPhotoExtraDataPath(path);

    CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CreateDirectory(cachePath), "", "Failed to creat dir");
    cachePath += "/livePhoto." + MediaFileUtils::GetExtensionFromPath(path);

    UniqueFd imageFd(open(path.c_str(), O_RDONLY));
    if (imageFd.Get() == E_ERR) {
        MEDIA_ERR_LOG("Failed to open iamge");
        return "";
    }
    UniqueFd videoFd(open(videoPath.c_str(), O_RDONLY));
    if (videoFd.Get() == E_ERR) {
        MEDIA_ERR_LOG("Failed to open video");
        return "";
    }
    UniqueFd livePhotoFd(open(cachePath.c_str(), O_WRONLY | O_CREAT, CHOWN_RO_USR_GRP));
    if (livePhotoFd.Get() == E_ERR) {
        MEDIA_ERR_LOG("Failed to open live photo");
        return "";
    }
    if (MergeFile(imageFd, videoFd, livePhotoFd, extraPath, GetFrameIndex(coverPosition, videoFd)) == E_ERR) {
        return "";
    }
    return cachePath;
}

bool IsLivePhoto(const std::string& path)
{
    if (access(path.c_str(), F_OK) != E_OK) {
        return false;
    }
    UniqueFd livePhotoFd(open(path.c_str(), O_RDONLY));
    if (livePhotoFd.Get() == E_ERR) {
        MEDIA_ERR_LOG("Failed to open live photo");
        return "";
    }
    if (GetFileSize(livePhotoFd) < LIVE_TAG_LEN) {
        return false;
    }
    off_t offset = lseek(livePhotoFd.Get(), -LIVE_TAG_LEN, SEEK_END);
    if (offset == E_ERR) {
        return false;
    }
    char buffer[LIVE_TAG_LEN + 1];
    ssize_t bytesRead = read(livePhotoFd.Get(), buffer, LIVE_TAG_LEN);
    if (bytesRead == E_ERR) {
        return false;
    }
    buffer[bytesRead] = '\0';
    for (uint32_t i = 0; i < LIVE_TAG.size(), i++) {
        if (LIVE_TAG[i] != buffer[i]) {
            return false;
        }
    }
    return true;
}