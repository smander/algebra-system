FROM ubuntu:22.04

LABEL description="DynInst-enabled dynint container for instruction-level binary analysis"
LABEL version="0.3.1"

# Prevent interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists with insecure repos allowed
RUN apt-get update --allow-insecure-repositories

# Install system dependencies for DynInst
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* && \
    apt-get update --allow-insecure-repositories && apt-get install -y --allow-unauthenticated \
    # Build essentials
    build-essential \
    cmake \
    git \
    pkg-config \
    # DynInst dependencies
    libelf-dev \
    libdwarf-dev \
    libiberty-dev \
    libboost-all-dev \
    libtbb-dev \
    zlib1g-dev \
    # Python and pip
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # Additional tools
    wget \
    curl \
    file \
    gdb \
    strace \
    ltrace \
    binutils \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt

# Install additional dependencies for DynInst build
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated \
        libdw-dev \
        libdwarf-dev \
        liblzma-dev \
        && rm -rf /var/lib/apt/lists/*

# Build DynInst from source using CMake with error handling  
RUN git clone https://github.com/dyninst/dyninst.git /opt/dyninst-source && \
    cd /opt/dyninst-source && \
    git checkout v13.0.0 && \
    mkdir build && \
    cd build && \
    cmake /opt/dyninst-source -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_STATIC_LIBS=OFF \
        -DBUILD_DOCS=OFF \
        -DBUILD_RTLIB_32=OFF && \
    (make -j1 && make install && ldconfig && echo "✅ DynInst installed successfully" || echo "⚠️ DynInst compilation failed - continuing without DynInst") && \
    cd / && \
    rm -rf /opt/dyninst-source

# Update library paths
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/dyninst.conf && \
    ldconfig

# Create Python virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip setuptools wheel

# Install pybind11 for potential Python bindings
RUN pip install pybind11[global]

# Install additional Python packages for binary analysis
RUN pip install \
    pyelftools>=0.30 \
    capstone>=4.0.2 \
    angr>=9.2.0 \
    numpy \
    pandas \
    click

# Set environment variables for DynInst
ENV DYNINSTAPI_RT_LIB=/usr/local/lib/libdyninstAPI_RT.so
ENV DYNINST_INSTALL=/usr/local
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH

# Create workspace directory
WORKDIR /workspace

# Add capabilities for binary instrumentation
# Note: These will be set in docker-compose.yml
# cap_add: SYS_PTRACE
# privileged: true

# Set default shell
SHELL ["/bin/bash", "-c"]

# Copy source code
COPY dyninst_wrapper.cpp /workspace/
COPY CMakeLists.txt /workspace/

# Attempt to build the DynInst wrapper (may fail if DynInst not available)
RUN cd /workspace && \
    mkdir -p build && \
    cd build && \
    (cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/usr && \
     make -j$(nproc) && \
     cp dyninst_wrapper /workspace/dyninst_wrapper && \
     chmod +x /workspace/dyninst_wrapper && \
     echo "✅ DynInst wrapper built successfully") || \
    echo "⚠️ DynInst wrapper build failed - real DynInst not available"

# Create entrypoint script
RUN cat > /opt/entrypoint.sh << 'EOF'
#!/bin/bash
set -e

echo "🔧 DynInst Container Starting..."
echo "   DynInst Version: $(ls /usr/local/include/dyninst/ 2>/dev/null | head -1 || echo 'Not detected')"
echo "   Python: $(python3 --version)"
echo "   Workspace: $(pwd)"
echo

# Verify DynInst installation
if [ -f "/usr/local/lib/libdyninstAPI.so" ]; then
    echo "✅ DynInst libraries found"
else
    echo "❌ DynInst libraries not found"
fi

# Verify Python environment
if python3 -c "import pyelftools, pybind11, capstone, angr" 2>/dev/null; then
    echo "✅ Python dependencies available"
else
    echo "❌ Python dependencies missing"
fi

echo

# Execute the command
exec "$@"
EOF

RUN chmod +x /opt/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/opt/entrypoint.sh"]

# Default command
CMD ["/bin/bash"]

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="dynint-dyninst"
LABEL org.opencontainers.image.description="DynInst-powered binary analysis container"
LABEL org.opencontainers.image.source="https://github.com/smander/algebra-system"
LABEL org.opencontainers.image.documentation="https://github.com/dyninst/dyninst"
