//===-- SystemLifetimeManager.cpp ------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/Initialization/SystemLifetimeManager.h"

#include "lldb/Core/Debugger.h"
#include "lldb/Initialization/SystemInitializer.h"

#include <utility>

using namespace lldb_private;

SystemLifetimeManager::SystemLifetimeManager()
    : m_mutex(), m_initialized(false) {}

SystemLifetimeManager::~SystemLifetimeManager() {
  assert(!m_initialized &&
         "SystemLifetimeManager destroyed without calling Terminate!");
}

void SystemLifetimeManager::Initialize(
    std::unique_ptr<SystemInitializer> initializer,
    LoadPluginCallbackType plugin_callback) {
  std::lock_guard<std::recursive_mutex> guard(m_mutex);
  if (!m_initialized) {
    assert(!m_initializer && "Attempting to call "
                             "SystemLifetimeManager::Initialize() when it is "
                             "already initialized");
    m_initialized = true;
    m_initializer = std::move(initializer);

    m_initializer->Initialize();
    Debugger::Initialize(plugin_callback);
  }
}

void SystemLifetimeManager::Terminate() {
  std::lock_guard<std::recursive_mutex> guard(m_mutex);

  if (m_initialized) {
    Debugger::Terminate();
    m_initializer->Terminate();

    m_initializer.reset();
    m_initialized = false;
  }
}
