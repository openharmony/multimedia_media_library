/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { Context, CreateOptions, MediaChangeRequest, PhotoCreateOptions, PhotoProxy } from "./media_library_common.ets";
import { PhotoAssetHandle } from "./photo_asset.ets";
import { ResourceType, PhotoType } from "./media_library_enum.ets";

class MediaAssetChangeRequestHandle implements MediaChangeRequest {
    static { loadLibrary("photo_access_helper_ani"); }
    private nativeHandle: long = 0;

    constructor(context: long) {
        if (this.nativeHandle == 0) {
            this.nativeHandle = context;
        }
    }

    native static create(asset: PhotoAssetHandle): MediaAssetChangeRequestHandle;
    native addResource(type: ResourceType, fileUri: string): void;
    native addResource(type: ResourceType, data: ArrayBuffer): void;
    native addResource(type: ResourceType, proxy: PhotoProxy): void;
    native static createAssetRequest(context: Context, displayName: string,
        options?: PhotoCreateOptions): MediaAssetChangeRequestHandle;
    native static createAssetRequest(context: Context, photoType: PhotoType, extension: string,
        options?: CreateOptions): MediaAssetChangeRequestHandle;
    native static createImageAssetRequest(context: Context, fileUri: string): MediaAssetChangeRequestHandle;
    native static createVideoAssetRequest(context: Context, fileUri: string): MediaAssetChangeRequestHandle;
    native getAsset(): PhotoAssetHandle;
    native static deleteAssetsByPhotoAssetSync(context: Context, assets: Array<PhotoAssetHandle>): void;
    native static deleteAssetsByUriListSync(context: Context, uriList: Array<string>): void;
}
