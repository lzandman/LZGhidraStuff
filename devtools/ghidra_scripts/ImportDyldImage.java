// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Leon Zandman

// Imports one image of a dyld shared cache into the project with Ghidra's DyldCacheExtractLoader,
// for analyzeHeadless runs without -import (which only takes local files). Arguments:
// <cache file> <install name> <program name> [<loader option> <value>]...
// The install name is the one in the cache (/System/Library/PrivateFrameworks/X.framework/
// Versions/A/X). Loader options go without the leading dash, because analyzeHeadless takes any
// argument that starts with one as its own: loader-authData true. Run the analysis afterwards
// with -process <program name>.
//@category LZGhidraStuff
import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.DyldCacheExtractLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemProbeConflictResolver;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.program.model.listing.Program;

public class ImportDyldImage extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		FileSystemService service = FileSystemService.getInstance();
		FSRL cache = service.getLocalFSRL(new File(args[0]));
		FSRL image;
		try (FileSystemRef ref = service.probeFileForFilesystem(cache, monitor,
			FileSystemProbeConflictResolver.CHOOSEFIRST)) {
			GFile file = ref == null ? null : ref.getFilesystem().lookup(args[1]);
			if (file == null) {
				printerr("Not in the cache: " + args[1]);
				return;
			}
			image = file.getFSRL();
		}
		MessageLog log = new MessageLog();
		ProgramLoader.Builder builder = ProgramLoader.builder()
				.source(image)
				.project(state.getProject())
				.projectFolderPath("/")
				.name(args[2])
				.loaders(DyldCacheExtractLoader.class)
				.log(log)
				.monitor(monitor);
		for (int i = 3; i + 1 < args.length; i += 2) {
			builder.addLoaderArg("-" + args[i], args[i + 1]);
		}
		try (LoadResults<Program> results = builder.load()) {
			Program program = results.getPrimaryDomainObject(this);
			println("ImportDyldImage: " + image.getPath() + " as " + args[2] + ", " +
				program.getMemory().getBlocks().length + " blocks");
			results.save(monitor);
			results.release(this);
		}
	}
}
