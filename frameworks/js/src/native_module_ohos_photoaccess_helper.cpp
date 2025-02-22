/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "cloud_enhancement_task_state_napi.h"
#include "cloud_enhancement_napi.h"
#include "cloud_media_asset_manager_napi.h"
#include "cloud_media_asset_status_napi.h"
#include "highlight_album_napi.h"
#include "media_album_change_request_napi.h"
#include "media_asset_change_request_napi.h"
#include "media_asset_edit_data_napi.h"
#include "media_asset_manager_napi.h"
#include "media_assets_change_request_napi.h"
#include "napi/native_node_api.h"
#include "native_module_ohos_medialibrary.h"
#include "photo_proxy_napi.h"

extern const char _binary_photoaccesshelperinf_js_start[];
extern const char _binary_photoaccesshelperinf_js_end[];
extern const char _binary_photoaccesshelperinf_abc_start[];
extern const char _binary_photoaccesshelperinf_abc_end[];

namespace OHOS {
namespace Media {
/*
 * Function registering all props and functions of userfilemanager module
 */
static napi_value PhotoAccessHelperExport(napi_env env, napi_value exports)
{
    MediaLibraryNapi::PhotoAccessHelperInit(env, exports);
    FetchFileResultNapi::PhotoAccessHelperInit(env, exports);
    FileAssetNapi::PhotoAccessHelperInit(env, exports);
    AlbumNapi::PhotoAccessHelperInit(env, exports);
    PhotoAlbumNapi::PhotoAccessInit(env, exports);
    HighlightAlbumNapi::AnalysisAlbumInit(env, exports);
    HighlightAlbumNapi::Init(env, exports);
    MediaAssetEditDataNapi::Init(env, exports);
    MediaAssetChangeRequestNapi::Init(env, exports);
    MediaAssetsChangeRequestNapi::Init(env, exports);
    MediaAlbumChangeRequestNapi::Init(env, exports);
    MediaAlbumChangeRequestNapi::MediaAnalysisAlbumChangeRequestInit(env, exports);
    MediaAssetManagerNapi::Init(env, exports);
    MovingPhotoNapi::Init(env, exports);
    PhotoProxyNapi::Init(env, exports);
    CloudEnhancementNapi::Init(env, exports);
    CloudEnhancementTaskStateNapi::Init(env, exports);
    CloudMediaAssetManagerNapi::Init(env, exports);
    CloudMediaAssetStatusNapi::Init(env, exports);
    return exports;
}

extern "C" __attribute__((visibility("default"))) void NAPI_file_photoAccessHelper_GetJSCode(const char** buf,
    int* bufLen)
{
    if (buf != nullptr) {
        *buf = _binary_photoaccesshelperinf_js_start;
    }

    if (bufLen != nullptr) {
        *bufLen = _binary_photoaccesshelperinf_js_end - _binary_photoaccesshelperinf_js_start;
    }
}

extern "C" __attribute__((visibility("default"))) void NAPI_file_photoAccessHelper_GetABCCode(const char** buf,
    int* bufLen)
{
    if (buf != nullptr) {
        *buf = _binary_photoaccesshelperinf_abc_start;
    }

    if (bufLen != nullptr) {
        *bufLen = _binary_photoaccesshelperinf_abc_end - _binary_photoaccesshelperinf_abc_start;
    }
}

/*
 * module define
 */
static napi_module g_photoAccessHelperModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = PhotoAccessHelperExport,
    .nm_modname = "file.photoAccessHelper",
    .nm_priv = reinterpret_cast<void *>(0),
    .reserved = {0}
};

/*
 * module register
 */
extern "C" __attribute__((constructor)) void RegisterPhotoAccessHelper(void)
{
    napi_module_register(&g_photoAccessHelperModule);
}
} // namespace Media
} // namespace OHOS