/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MEDIA_LIBRARY_MEDIA_SCAN_FILE_MANAGER_FILE_H
#define MEDIA_LIBRARY_MEDIA_SCAN_FILE_MANAGER_FILE_H

#include "dfx_utils.h"
#include "i_processor.h"
#include "media_file_notify_info.h"
#include "media_log.h"
#include "file_manager_scanner.h"

namespace OHOS {
namespace Media {
class MediaScanFileManagerFileProcessor : public IProcessor {
public:
    void Process(const MediaNotifyInfo &notifyInfo) override
    {
        CHECK_AND_RETURN_LOG(notifyInfo.afterPath != "", "Invalid path in MediaScanFileManagerFileProcessor.");
        MEDIA_INFO_LOG("Process in MediaScanFileManagerFileProcessor, path: %{public}s",
            DfxUtils::GetSafePath(notifyInfo.afterPath).c_str());
        std::vector<MediaNotifyInfo> input = {notifyInfo};
        FileManagerScanner scanner;
        scanner.Run(input);
    }
};
}
}

#endif // MEDIA_LIBRARY_MEDIA_SCAN_FILE_MANAGER_FILE_H