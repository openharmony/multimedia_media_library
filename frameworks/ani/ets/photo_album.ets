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

import { FetchResultHandle } from "./fetch_result.ets";
import { PhotoAssetHandle } from "./photo_asset.ets";
import { FetchOptionsInner } from "./media_library_common.ets";
import { AlbumType, AlbumSubtype } from "./media_library_enum.ets";

export class AlbumHandle {
    // AbsAlbum
    readonly albumType: AlbumType;
    readonly albumSubtype: AlbumSubtype;
    albumName: string = '';
    readonly albumUri: string = '';
    readonly count: number;
    readonly coverUri: string = '';

    // Album
    readonly imageCount: number | undefined;
    readonly videoCount: number | undefined;

    private  nativePhotoAlbum: long = 0;

    constructor(nativePtr: long) {
        if (this.nativePhotoAlbum == 0) {
            this.nativePhotoAlbum = nativePtr;
        }
    }

    native static create(): AlbumHandle;
    native getAssetsInner(options: FetchOptionsInner): FetchResultHandle<PhotoAssetHandle>;
    native getAssetsSync(options: FetchOptionsInner): Array<PhotoAssetHandle>;
    native commitModifyInner(): void;
    native addAssetsInner(assets: Array<PhotoAssetHandle>): void;
    native removeAssetsInner(assets: Array<PhotoAssetHandle>): void;
    native recoverAssetsInner(assets: Array<PhotoAssetHandle>): void;
    native deleteAssetsInner(assets: Array<PhotoAssetHandle>): void;
    native setCoverUriInner(uri: string): void;
    native getFaceIdInner(): string;
}