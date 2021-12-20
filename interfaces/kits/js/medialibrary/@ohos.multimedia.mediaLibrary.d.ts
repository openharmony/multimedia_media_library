/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

import { AsyncCallback } from './basic';

declare namespace mediaLibrary {

    /**
     * Returns an instance of MediaLibraryHelper
     *
     * @return Instance of MediaLibraryHelper
     * @version1
     */
    function getMediaLibrary(): MediaLibrary;

    // OLD API for getting the Media Library instance. This will be deprecated
    // once all applications have migrated to using new API
    function getMediaLibraryHelper(): MediaLibrary;

    /**
     * Enumeration types for different kind of Media Files
     *
     * @version1
     */
    enum MediaType {
        DEFAULT = 0,            // OLD API
        FILE,
        MEDIA,                  // OLD API
        IMAGE,
        VIDEO,
        AUDIO,
        ALBUM_LIST,             // OLD API
        ALBUM_LIST_INFO         // OLD API
    }

    enum ErrorCode {
        ERR_FAIL = -1,
        ERR_SUCCESS = 0
    }

    /**
     * OLD API
     * Defines the media asset.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export interface MediaAsset {
        id: number;
        URI: string;
        mediaType: MediaType;
        name: string;
        size: number;
        dateAdded: number;
        dateModified: number;
        albumId: number;
        albumName: string;

        /**
         * Start setting the properties for a newly created media asset
         *
         * @return Returns whether property setting can be started for a created media asset
         * @version 1
         */
        startCreate(callback: AsyncCallback<boolean>): void;
        startCreate(): Promise<boolean>;

        /**
         * Start modifying the properties for an existing media asset
         *
         * @return Returns whether property modification can be started for a media asset
         * @version 1
         */
        startModify(callback: AsyncCallback<boolean>): void;
        startModify(): Promise<boolean>;

        /**
         * Cancel the creation of a media asset
         *
         * @return Returns whether creation of a media asset was cancelled or not
         * @version 1
         */
        cancelCreate(callback: AsyncCallback<boolean>): void;
        cancelCreate(): Promise<boolean>;

        /**
         * Cancel the modification of a media asset
         *
         * @return Returns whether modification of a media asset was cancelled or not
         * @version 1
         */
        cancelModify(callback: AsyncCallback<boolean>): void;
        cancelModify(): Promise<boolean>;

        /**
         * Commit the creation of a media asset
         *
         * @return Returns whether creation of a media asset was committed or not
         * @version 1
         */
        commitCreate(callback: AsyncCallback<boolean>): void;
        commitCreate(): Promise<boolean>;

        /**
         * Delete a media asset
         *
         * @return Returns whether deletion of a media asset was successful or not
         * @version 1
         */
        commitDelete(callback: AsyncCallback<boolean>): void;
        commitDelete(): Promise<boolean>;

        /**
         * Commit the modification of a media asset
         *
         * @return Returns whether modification of a media asset was committed or not
         * @version 1
         */
        commitModify(callback: AsyncCallback<boolean>): void;
        commitModify(): Promise<boolean>;

        /**
         * Copy a media asset properties to the target media asset
         *
         * @param target The target media asset on which the source properties are to be copied
         * @return Returns whether copying of a media asset to the target was successful or not
         * @version 1
         */
        commitCopy(target: MediaAsset, callback: AsyncCallback<boolean>): void;
        commitCopy(target: MediaAsset): Promise<boolean>;
    }

    /**
     * OLD API
     * Defines the audio asset.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export interface AudioAsset extends MediaAsset {
        mimeType: string;
        title: string;
        artist: string;
        duration: number;
    }

    /**
     * OLD API
     * Defines the video asset.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export interface VideoAsset extends MediaAsset {
        mimeType: string;
        width: number;
        height: number;
        duration: number;
    }

    /**
     * OLD API
     * Defines the image asset.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export interface ImageAsset extends MediaAsset {
        mimeType: string;
        width: number;
        height: number;
    }

    /**
     * Defines the album.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export interface Album {
        albumId?: number;
        albumName: string;

        virtual: boolean;

        path?: string;
        relativePath: string;

        dateModified?: number;

        // get all FileAssets in each album
        getFileAssets(options: MediaFetchOptions, callback: AsyncCallback<FetchFileResult>): void;
        getFileAssets(options: MediaFetchOptions): Promise<FetchFileResult>;

        /**
         * OLD API
         * Gets all video assets in album.
         *
         * @return Returns video assets list as asynchronous response
         * @version 1
         */
        getVideoAssets(): Promise<VideoAssets>;
        getVideoAssets(callback: AsyncCallback<VideoAssets>): void;

        /**
         * OLD API
         * Gets all image assets in album.
         *
         * @return Returns image assets list as asynchronous response
         * @version 1
         */
        getImageAssets(): Promise<ImageAssets>;
        getImageAssets(callback: AsyncCallback<ImageAssets>): void;

        /**
         * OLD API
         * Commit the creation of an album
         *
         * @return Returns whether creation of an album was committed or not
         * @version 1
         */
        commitCreate(callback: AsyncCallback<boolean>): void;
        commitCreate(): Promise<boolean>;

        /**
         * OLD API
         * Delete an album
         *
         * @return Returns whether deletion of an album was successful or not
         * @version 1
         */
        commitDelete(callback: AsyncCallback<boolean>): void;
        commitDelete(): Promise<boolean>;

        /**
         * OLD API
         * Commit the modification of an album
         *
         * @return Returns whether modification of an album was committed or not
         * @version 1
         */
        commitModify(callback: AsyncCallback<boolean>): void;
        commitModify(): Promise<boolean>;
    }

    interface FileAsset {
        id?: number;
        uri?: string;
        thumbnailUri?: string;

        path?: string;
        relativePath: string;

        mimeType?: string;
        mediaType: MediaType;

        displayName: string;
        size?: number;

        dateAdded?: number;
        dateModified?: number;

        // audio
        title?: string;
        artist?: string;
        album?: string;

        // image & video
        width?: number;
        height?: number;
        duration?: number;
        orientation?: number;

        // album
        albumId?: number;
        albumName?: string;
    }

    enum FileKey {
        ID = "id",
        PATH = "path",
        RELATIVE_PATH = "relative_path",
        MIME_TYPE = "mime_type",
        MEDIA_TYPE = "media_type",
        DISPLAY_NAME = "display_name",
        SIZE = "size",
        DATE_ADDED = "date_added",
        DATE_MODIFIED = "date_modified",
        TITLE = "title",
        ARTIST = "artist",
        ALBUM = "album",
        ALBUM_ID = "album_id",
        ALBUM_NAME = "album_name",
    }

    /**
     * Fetch parameters applicable on images, videos, audios, albums and other media
     *
     * @version 1
     */
    export interface MediaFetchOptions {
        selections: string;
        selectionArgs: Array<string>;
        order: string;
    }

    interface FetchFileResult {
        // get count
        getCount(): number;

        // is after the last
        isAfterLast(): boolean;

        // get the first FileAsset from the results
        getFirstObject(callback: AsyncCallback<FileAsset>): void;
        getFirstObject(): Promise<FileAsset>;

        // get the next FileAsset from the results
        getNextObject(callback: AsyncCallback<FileAsset>): void;
        getNextObject(): Promise<FileAsset>;

        // get the last FileAsset from the results
        getLastObject(callback: AsyncCallback<FileAsset>): void;
        getLastObject(): Promise<FileAsset>;

        // get the FileAsset at the posion from the results
        getPositionObject(index: number, callback: AsyncCallback<FileAsset>): void;
        getPositionObject(index: number): Promise<FileAsset>;

        // query for all asset at a time and return an array
        getAllObject(callback: AsyncCallback<Array<FileAsset>>): void;
        getAllObject(): Promise<Array<FileAsset>>;
    }

    interface MediaChangeListener {
        mediaType: MediaType;
    }

    type MediaAssets = Array<Readonly<MediaAsset>>;    // OLD API

    type AudioAssets = Array<Readonly<AudioAsset>>;    // OLD API

    type VideoAssets = Array<Readonly<VideoAsset>>;    // OLD API

    type ImageAssets = Array<Readonly<ImageAsset>>;    // OLD API

    type Albums = Array<Readonly<Album>>;

    /**
     * Defines the MediaLibraryHelper class and provides functions to access the data in media storage.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
    export class MediaLibrary {

        // query all assets just for count & first cover
        // if need all data, getAllObject from FetchFileResult
        getFileAssets(options: MediaFetchOptions, callback: AsyncCallback<FetchFileResult>): void;
        getFileAssets(options: MediaFetchOptions): Promise<FetchFileResult>;

        // query an entity album
        getAlbums(options: MediaFetchOptions, callback: AsyncCallback<Array<Album>>): void;
        getAlbums(options: MediaFetchOptions): Promise<Array<Album>>;

        // subscribe a media change, can be a combination of each MediaType
        on(type: 'image' | 'video' | 'audio' | 'file', callback: AsyncCallback<MediaChangeListener>): void;

        // unsubscribe a media change
        off(type: 'image' | 'video' | 'audio' | 'file', callback?: AsyncCallback<MediaChangeListener>): void;

        // file operation
        createAsset(targetAsset: FileAsset, callback: AsyncCallback<string>): void;
        createAsset(targetAsset: FileAsset): Promise<string>;

        modifyAsset(uri: string, targetAsset: FileAsset, callback: AsyncCallback<ErrorCode>): void;
        modifyAsset(uri: string, targetAsset: FileAsset): Promise<ErrorCode>;

        deleteAsset(uri: string, callback: AsyncCallback<ErrorCode>): void;
        deleteAsset(uri: string): Promise<ErrorCode>;

        openAsset(uri: string, mode: string, callback: AsyncCallback<number>): void;
        openAsset(uri: string, mode: string): Promise<number>;

        closeAsset(uri: string, fd: number, callback: AsyncCallback<ErrorCode>): void;
        closeAsset(uri: string, fd: number): Promise<ErrorCode>;

        // album operation
        createNewAlbum(targetAlbum: Album, callback: AsyncCallback<number>): void;
        createNewAlbum(targetAlbum: Album): Promise<number>;

        modifyAlbum(albumId: number, targetAlbum: Album, callback: AsyncCallback<ErrorCode>): void;
        modifyAlbum(albumId: number, targetAlbum: Album): Promise<ErrorCode>;

        deleteAlbum(albumId: number, callback: AsyncCallback<ErrorCode>): void;
        deleteAlbum(albumId: number): Promise<ErrorCode>;

        /**
         * OLD API
         * Gets all media assets from system.
         *
         * @param options Fetch options with selection strings based on which to select the media assets
         * @return Returns media assets list as asynchronous response
         * @version 1
         */
        getMediaAssets(callback: AsyncCallback<MediaAssets>): void;
        getMediaAssets(options: MediaFetchOptions, callback: AsyncCallback<MediaAssets>): void;
        getMediaAssets(options?: MediaFetchOptions): Promise<MediaAssets>;

        /**
         * OLD API
         * Gets all audio assets from system.
         *
         * @param options Fetch options with selection strings based on which to select the audio assets
         * @return Returns audio assets list as asynchronous response
         * @version 1
         */
        getAudioAssets(callback: AsyncCallback<AudioAssets>): void;
        getAudioAssets(options: MediaFetchOptions, callback: AsyncCallback<AudioAssets>): void;
        getAudioAssets(options?: MediaFetchOptions): Promise<AudioAssets>;

        /**
         * OLD API
         * Gets all video assets from system.
         *
         * @param options Fetch options with selection strings based on which to select the video assets
         * @return Returns video assets list as asynchronous response
         * @version 1
         */
        getVideoAssets(callback: AsyncCallback<VideoAssets>): void;
        getVideoAssets(options: MediaFetchOptions, callback: AsyncCallback<VideoAssets>): void;
        getVideoAssets(options?: MediaFetchOptions): Promise<VideoAssets>;

        /**
         * OLD API
         * Gets all image assets from system.
         *
         * @param options Fetch options with selection strings based on which to select the image assets
         * @return Returns image assets list as asynchronous response
         * @version 1
         */
        getImageAssets(callback: AsyncCallback<ImageAssets>): void;
        getImageAssets(options: MediaFetchOptions, callback: AsyncCallback<ImageAssets>): void;
        getImageAssets(options?: MediaFetchOptions): Promise<ImageAssets>;

        /**
         * OLD API
         * Gets video album from system
         *
         * @param options Fetch options with selection strings based on which to select the albums
         * @return Returns video album as asynchronous response
         * @version 1
         */
        getVideoAlbums(options: MediaFetchOptions, callback: AsyncCallback<Albums>): void;
        getVideoAlbums(options: MediaFetchOptions): Promise<Albums>;

        /**
         * OLD API
         * Gets image album from system
         *
         * @param options Fetch options with selection strings based on which to select the albums
         * @return Returns image album as asynchronous response
         * @version 1
         */
        getImageAlbums(options: MediaFetchOptions, callback: AsyncCallback<Albums>): void;
        getImageAlbums(options: MediaFetchOptions): Promise<Albums>;

        /**
         * OLD API
         * Create a video asset with empty properties
         *
         * @return Returns a video asset as asynchronous response
         * @version 1
         */
        createVideoAsset(callback: AsyncCallback<VideoAsset>): void;
        createVideoAsset(): Promise<VideoAsset>;

        /**
         * OLD API
         * Create an image asset with empty properties
         *
         * @return Returns an image asset as asynchronous response
         * @version 1
         */
        createImageAsset(callback: AsyncCallback<ImageAsset>): void;
        createImageAsset(): Promise<ImageAsset>;

        /**
         * OLD API
         * Create an audio asset with empty properties
         *
         * @return Returns an audio asset as asynchronous response
         * @version 1
         */
        createAudioAsset(callback: AsyncCallback<AudioAsset>): void;
        createAudioAsset(): Promise<AudioAsset>;

        /**
         * OLD API
         * Create an album with empty properties
         *
         * @return Returns an album as asynchronous response
         * @version 1
         */
        createAlbum(callback: AsyncCallback<Album>): void;
        createAlbum(): Promise<Album>;
    }

    enum MetadataCode {
        AV_KEY_CD_TRACK_NUMBER = 0,
        AV_KEY_ALBUM = 1,
        AV_KEY_ARTIST = 2,
        AV_KEY_AUTHOR = 3,
        AV_KEY_COMPOSER = 4,
        AV_KEY_DATE = 5,
        AV_KEY_GENRE = 6,
        AV_KEY_TITLE = 7,
        AV_KEY_YEAR = 8,
        AV_KEY_DURATION = 9,
        AV_KEY_NUM_TRACKS = 10,
        AV_KEY_WRITER = 11,
        AV_KEY_MIME_TYPE = 12,
        AV_KEY_ALBUM_ARTIST = 13,
        AV_KEY_DISC_NUMBER = 14,
        AV_KEY_COMPILATION = 15,
        AV_KEY_HAS_AUDIO = 16,
        AV_KEY_HAS_VIDEO = 17,
        AV_KEY_VIDEO_WIDTH = 18,
        AV_KEY_VIDEO_HEIGHT = 19,
        AV_KEY_BITRATE = 20,
        AV_KEY_TIMED_TEXT_LANGUAGES = 21,
        AV_KEY_IS_DRM = 22,
        AV_KEY_LOCATION = 23,
        AV_KEY_VIDEO_ROTATION = 24,
        AV_KEY_CAPTURE_FRAMERATE = 25,
        AV_KEY_HAS_IMAGE = 26,
        AV_KEY_IMAGE_COUNT = 27,
        AV_KEY_IMAGE_PRIMARY = 28,
        AV_KEY_IMAGE_WIDTH = 29,
        AV_KEY_IMAGE_HEIGHT = 30,
        AV_KEY_IMAGE_ROTATION = 31,
        AV_KEY_VIDEO_FRAME_COUNT = 32,
        AV_KEY_EXIF_OFFSET = 33,
        AV_KEY_EXIF_LENGTH = 34,
        AV_KEY_COLOR_STANDARD = 35,
        AV_KEY_COLOR_TRANSFER = 36,
        AV_KEY_COLOR_RANGE = 37,
        AV_KEY_SAMPLE_RATE = 38,
        AV_KEY_BITS_PER_SAMPLE = 39,
    }

    function getAVMetadataHelper(): AVMetadataHelper;

    interface AVMetadataHelper {
        // set source by string, string like dataability:///external/media
        setSource(uri: string, callback: AsyncCallback<void>): void;
        setSource(uri: string): Promise<void>;

        // fetch video frame pixelmap by time
        fetchVideoPixelMapByTime(timeMs: number, callback: AsyncCallback<image.PixelMap>): void;
        fetchVideoPixelMapByTime(timeMs: number): Promise<image.PixelMap>;

        // fetch metadata
        resolveMetadata(key: MetadataCode, callback: AsyncCallback<string>): void;
        resolveMetadata(key: MetadataCode): Promise<string>;

        // release
        release(callback: AsyncCallback<void>): void;
        release(): Promise<void>;
    }

    enum ScanState {
        SCAN_ERROR = -1,
        SCAN_SUCCESS = 0,
        SCAN_EMPTY_ARGS = 1,
        SCAN_NOT_ACCESSIBLE = 2,
        SCAN_INCORRECT_PATH = 3,
        SCAN_MEM_ALLOC_FAIL = 4,
        SCAN_MIMETYPE_NOTSUPPORT = 5,
        SCAN_SCAN_NOT_INIT = 6,
        SCAN_SERVICE_NOT_READY = 7,
        SCAN_INV_CB_ERR = 8
    }

    /**
     * Defines the scan result.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
     interface ScanResult {
        status : ScanState;
        // fileUri will be an URI when we call scanFile API & in scanDir API call it will be blank
        fileUri : string;
    }

    /**
     * Returns an instance of MediaScannerHelper
     *
     * @return Instance of MediaScannerHelper
     * @version1
     */
    function getScannerInstance(): MediaScannerHelper;

    /**
     * Defines the MediaScannerHelper class and provides functions to scan the specified dir/file of media storage.
     *
     * @SysCap SystemCapability.Multimedia.MediaLibrary
     * @devices common
     * @version 1
     */
     class MediaScannerHelper {
        /**
         * This API will help to scan the specified directory and updates the metadata to database
         *
         * @param scanDirPath Valid path to a directory {/data/media}
         * @param callback Callback object to be passed along with request
         * @return int32_t Returns the scan state of scanDir
         * @version 1
         */
        scanDir(scanDirPath: string, callback: AsyncCallback<ScanResult>): void;
        scanDir(scanDirPath: string): Promise<ScanResult>;

        /**
         * This API will help to scan the specified file and updates the metadata to database
         *
         * @param scanFilePath Valid path to a file along with filename{/data/media/sample.mp3}
         * @param callback Callback object to be passed along with request
         * @return int32_t Returns the scan state of scanFile
         * @version 1
         */
        scanFile(scanFilePath: string, callback: AsyncCallback<ScanResult>): void;
        scanFile(scanFilePath: string): Promise<ScanResult>;
     }
}
